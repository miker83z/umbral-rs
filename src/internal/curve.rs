use crate::internal::errors::PreErrors;
use crate::internal::schemes::{unsafe_hash_to_point, Blake2bHash};

use std::ops::{Add, Div, Mul, Sub};
use std::{cell::RefCell, rc::Rc};

use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::ec::{EcGroup, EcGroupRef, EcPoint, EcPointRef, PointConversionForm};
use openssl::nid::Nid;
use std::fmt;
pub struct Params {
    group: EcGroup,
    g_point: EcPoint,
    order: BigNum,
    u_point: EcPoint,
    field_order_size_in_bytes: usize,
    group_order_size_in_bytes: usize,
    ctx: Rc<RefCell<BigNumContext>>,
}

impl Params {
    pub fn new(curve_name: Nid) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let group = EcGroup::from_curve_name(curve_name).expect("Curve name error");
        let g_point = group.generator().to_owned(&group).unwrap();
        let mut order = BigNum::new().unwrap();
        group.order(&mut order, &mut ctx).unwrap();
        let field_order_size_in_bytes = ((group.degree() + 7) / 8) as usize;
        let group_order_size_in_bytes = order.num_bytes() as usize;
        let u_point = unsafe_hash_to_point::<Blake2bHash>(
            Some(
                &g_point
                    .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
                    .expect("Error in Generator conversion"),
            ),
            Some(&b"NuCypher/UmbralParameters/u".to_vec()),
            &group,
            &mut ctx,
        );
        Params {
            group,
            g_point,
            order,
            u_point,
            field_order_size_in_bytes,
            group_order_size_in_bytes,
            ctx: Rc::new(RefCell::new(ctx)),
        }
    }

    pub fn group(&self) -> &EcGroupRef {
        &self.group
    }

    pub fn g_point(&self) -> &EcPointRef {
        &self.g_point
    }

    pub fn order(&self) -> &BigNumRef {
        &self.order
    }

    pub fn u_point(&self) -> &EcPointRef {
        &self.u_point
    }

    pub fn field_order_size_in_bytes(&self) -> usize {
        self.field_order_size_in_bytes
    }

    pub fn group_order_size_in_bytes(&self) -> usize {
        self.group_order_size_in_bytes
    }

    pub fn ctx(&self) -> &Rc<RefCell<BigNumContext>> {
        &self.ctx
    }

    pub fn eq(&self, other: &Params) -> bool {
        self.group
            .curve_name()
            .unwrap()
            .eq(&other.group.curve_name().unwrap())
    }
}

// #[derive(Debug)]
pub struct CurveBN {
    bn: BigNum,
    params: Rc<Params>,
}

impl CurveBN {
    pub fn new(params: &Rc<Params>) -> Self {
        CurveBN {
            bn: BigNum::new().expect("Error in BN creation"),
            params: Rc::clone(params),
        }
    }

    pub fn from_u32(n: u32, params: &Rc<Params>) -> Self {
        CurveBN {
            bn: BigNum::from_u32(n).expect("Error in BN creation"),
            params: Rc::clone(params),
        }
    }

    pub fn from_big_num(n: &BigNumRef, params: &Rc<Params>) -> Self {
        CurveBN {
            bn: n.to_owned().expect("Error in BN cloning"),
            params: Rc::clone(params),
        }
    }

    pub fn from_bytes(bytes: &Vec<u8>, params: &Rc<Params>) -> Result<Self, PreErrors> {
        if bytes.len() != Self::expected_bytes_length(params) {
            return Err(PreErrors::InvalidBytes);
        }
        let bn = BigNum::from_slice(&bytes).expect("Error in BN conversion");
        if Self::bn_is_on_curve(&bn, params) {
            Ok(CurveBN {
                bn,
                params: Rc::clone(params),
            })
        } else {
            Err(PreErrors::InvalidBytes)
        }
    }

    pub fn to_owned(&self) -> Self {
        CurveBN {
            bn: self.bn.to_owned().expect("Error in BN cloning"),
            params: Rc::clone(&self.params),
        }
    }

    pub fn rand_curve_bn(params: &Rc<Params>) -> Self {
        let mut rand = BigNum::new().unwrap();
        loop {
            params
                .order()
                .rand_range(&mut rand)
                .expect("Error in Randomization");
            if CurveBN::bn_is_on_curve(&rand, params) {
                break;
            }
        }

        CurveBN {
            bn: rand,
            params: Rc::clone(params),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut right = self.bn.to_vec();
        let rem = (self.params.group_order_size_in_bytes() as i64) - (right.len() as i64);
        if rem < 0 {
            panic!("Error: BN size too large");
        }
        let mut left = vec![0_u8; rem as usize];
        left.append(&mut right);
        left
    }

    fn bn_is_on_curve(bn: &BigNumRef, params: &Rc<Params>) -> bool {
        let zero = BigNum::new().unwrap();
        bn > &zero && bn < params.order()
    }

    pub fn expected_bytes_length(params: &Rc<Params>) -> usize {
        params.group_order_size_in_bytes()
    }

    pub fn eq(&self, other: &CurveBN) -> bool {
        if self.params.eq(&other.params) && self.bn.eq(&other.bn) {
            return true;
        }
        return false;
    }

    pub fn invert(&self) -> Self {
        let mut res = BigNum::new().expect("Error in BN creation");
        res.mod_inverse(
            &self.bn,
            self.params.order(),
            &mut self.params.ctx().borrow_mut(),
        )
        .expect("Error in BN addition");

        CurveBN {
            bn: res,
            params: Rc::clone(&self.params),
        }
    }

    pub fn bn(&self) -> &BigNumRef {
        &self.bn
    }

    pub fn params(&self) -> &Rc<Params> {
        &self.params
    }
}

impl Add for &CurveBN {
    type Output = CurveBN;

    fn add(self, other: &CurveBN) -> CurveBN {
        let mut res = BigNum::new().expect("Error in BN creation");
        res.mod_add(
            &self.bn,
            &other.bn,
            self.params.order(),
            &mut self.params.ctx().borrow_mut(),
        )
        .expect("Error in BN addition");

        CurveBN {
            bn: res,
            params: Rc::clone(&self.params),
        }
    }
}

impl Sub for &CurveBN {
    type Output = CurveBN;

    fn sub(self, other: &CurveBN) -> CurveBN {
        let mut res = BigNum::new().expect("Error in BN creation");
        res.mod_sub(
            &self.bn,
            &other.bn,
            self.params.order(),
            &mut self.params.ctx().borrow_mut(),
        )
        .expect("Error in BN addition");

        CurveBN {
            bn: res,
            params: Rc::clone(&self.params),
        }
    }
}

impl Mul for &CurveBN {
    type Output = CurveBN;

    fn mul(self, other: &CurveBN) -> CurveBN {
        let mut res = BigNum::new().expect("Error in BN creation");
        res.mod_mul(
            &self.bn,
            &other.bn,
            self.params.order(),
            &mut self.params.ctx().borrow_mut(),
        )
        .expect("Error in BN addition");

        CurveBN {
            bn: res,
            params: Rc::clone(&self.params),
        }
    }
}

impl Div for &CurveBN {
    type Output = CurveBN;

    fn div(self, other: &CurveBN) -> CurveBN {
        let inverse = other.invert();
        let mut res = BigNum::new().expect("Error in BN creation");
        res.mod_mul(
            &self.bn,
            &inverse.bn,
            self.params.order(),
            &mut self.params.ctx().borrow_mut(),
        )
        .expect("Error in BN addition");

        CurveBN {
            bn: res,
            params: Rc::clone(&self.params),
        }
    }
}

pub struct CurvePoint {
    point: EcPoint,
    params: Rc<Params>,
}

impl CurvePoint {
    pub fn new(params: &Rc<Params>) -> Self {
        CurvePoint {
            point: EcPoint::new(params.group()).expect("Error in Point creation"),
            params: Rc::clone(params),
        }
    }

    pub fn from_ec_point(p: &EcPointRef, params: &Rc<Params>) -> Self {
        CurvePoint {
            point: p.to_owned(params.group()).expect("Error in Point cloning"),
            params: Rc::clone(params),
        }
    }

    pub fn from_bytes(bytes: &Vec<u8>, params: &Rc<Params>) -> Result<Self, PreErrors> {
        if bytes.len() != Self::expected_bytes_length(params) {
            return Err(PreErrors::InvalidBytes);
        }
        match EcPoint::from_bytes(params.group(), bytes, &mut params.ctx().borrow_mut()) {
            Ok(point) => Ok(CurvePoint {
                point,
                params: Rc::clone(params),
            }),
            Err(err) => {
                println!("{}", err);
                Err(PreErrors::InvalidBytes)
            }
        }
    }

    pub fn mul_gen(other: &CurveBN, params: &Rc<Params>) -> Self {
        let mut res = EcPoint::new(params.group()).expect("Error in Point creation");
        res.mul_generator(params.group(), &other.bn, &params.ctx().borrow())
            .expect("Error in Point multiplication");

        CurvePoint {
            point: res,
            params: Rc::clone(params),
        }
    }

    pub fn expected_bytes_length(params: &Rc<Params>) -> usize {
        //assumess compressed, if not compressed = 1 + 2 * field_size,
        1 + params.field_order_size_in_bytes()
    }

    pub fn to_owned(&self) -> Self {
        CurvePoint {
            point: self
                .point
                .to_owned(self.params.group())
                .expect("Error in Point cloning"),
            params: Rc::clone(&self.params),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point
            .to_bytes(
                &self.params.group,
                PointConversionForm::COMPRESSED,
                &mut self.params.ctx().borrow_mut(),
            )
            .expect("Error in Point to bytes")
    }

    pub fn eq(&self, other: &CurvePoint) -> bool {
        if self.params.eq(&other.params)
            && self
                .point
                .eq(
                    self.params.group(),
                    &other.point,
                    &mut self.params.ctx().borrow_mut(),
                )
                .expect("Error in Point comparison")
        {
            return true;
        }
        return false;
    }

    pub fn point(&self) -> &EcPointRef {
        &self.point
    }

    pub fn params(&self) -> &Rc<Params> {
        &self.params
    }
}

impl Add for &CurvePoint {
    type Output = CurvePoint;

    fn add(self, other: &CurvePoint) -> CurvePoint {
        let mut res = EcPoint::new(self.params.group()).expect("Error in Point creation");
        res.add(
            self.params.group(),
            &self.point,
            &other.point,
            &mut self.params.ctx().borrow_mut(),
        )
        .expect("Error in Point addition");

        CurvePoint {
            point: res,
            params: Rc::clone(&self.params),
        }
    }
}

impl Mul<&CurveBN> for &CurvePoint {
    type Output = CurvePoint;

    fn mul(self, other: &CurveBN) -> CurvePoint {
        let mut res = EcPoint::new(self.params.group()).expect("Error in Point creation");
        res.mul(
            self.params.group(),
            &self.point,
            &other.bn,
            &self.params.ctx().borrow(),
        )
        .expect("Error in Point multiplication");

        CurvePoint {
            point: res,
            params: Rc::clone(&self.params),
        }
    }
}

impl fmt::Debug for CurveBN {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // write the struct fields in the desired format
        write!(f, "CurveBN {{ bn: {:?}}}", self.bn)
    }
}

impl Clone for CurveBN {
    fn clone(&self) -> Self {
        CurveBN {
            bn: self.bn.to_owned().expect("Error in BN cloning"),
            params: Rc::clone(&self.params),
        }
    }
}
