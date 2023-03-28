# GO Signal POC 🔐

This is a simple project which aimed to implement the entire [Signal protocol](https://signal.org/docs) in go, it was abandoned.  
Everyone is free to use it, fork it, modify it and maybe even continue it.

> **Note**
> If you want to continue this project, feel free to do so, just [let me know](https://t.me/cagavo) so i can link your fork here.

It only implements the [X3DH](https://signal.org/docs/specifications/x3dh/) key exchange using [XEdDSA](https://signal.org/docs/specifications/xeddsa/).  
The XEdDSA code was taken from [smallstep/crypto](https://github.com/smallstep/crypto) which is licensed under the Apache License 2.0.  
This code uses the 25519 curve but it shouldn't be hard to change it to the 448 curve. 

It was written following the [Signal protocol specification](https://signal.org/docs/).

> **Warning**
> This code is not secure, it was written just for fun and to learn about the signal protocol.  
> I don't recommend using it in production.

> **Note**
> This was tested only on windows but it should work everywhere, however i don't have plans to update it anymore.

## Usage

Build the project with ```go build``` and run it with ```./godh```.

## Warning

This code is not affiliated in any way with the Signal Foundation.