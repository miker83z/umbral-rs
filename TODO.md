# Title: TODO

A list of things to do for the project

- [ ] fix update error

```
error[E0422]: cannot find struct, variant or union type `Payload` in this scope
   --> src/internal/schemes.rs:244:20
    |
244 |         Some(a) => Payload {
    |                    ^^^^^^^ not found in this scope

    |
248 |         None => Payload {
    |                 ^^^^^^^ not found in this scope

    |
274 |         Some(a) => Payload {
    |                    ^^^^^^^ not found in this scope

    |
278 |         None => Payload {
    |                 ^^^^^^^ not found in this scope

    |
35  |     digest: Blake2b,
    |             ^^^^^^^ expected 1 generic argument
    |

note: type alias defined here, with 1 generic parameter: `OutSize`
   --> /Users/fadi/.cargo/registry/src/github.com-1ecc6299db9ec823/blake2-0.10.5/src/lib.rs:135:10
    |
135 | pub type Blake2b<OutSize> = CoreWrapper<Blake2bCore<OutSize>>;
    |          ^^^^^^^ -------
help: add missing generic argument
    |
35  |     digest: Blake2b<OutSize>,
    |             ~~~~~~~~~~~~~~~~
```

- [ ] Solve DPSS
