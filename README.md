# filetap

See what files a command actually touches.

```
filetap -- npm test
```

Linux only. This is early: right now it runs the command under ptrace and
reports how it exited, but doesn't show any file access yet.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in filetap by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
