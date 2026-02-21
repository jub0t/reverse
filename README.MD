# Suggest a name guys (avoid the letter "z")


### Usaage

```ts
.{
    .name = .zproxy_config,
    .fingerprint = 0x0000000000000001,
    .bind = "0.0.0.0",
    .port = 8080,
    .workers = 0,
    .backlog = 4096,
    .upstream = .{
        .addrs = .{"127.0.0.1:3000"},
        .strategy = .round_robin,
        .pool_size = 64,
    },
    .log_level = .info,
}
```

### Roadmap
- [ ] Benchmarking
- [ ] Stress Tests

### Exit

```sh
## This will come in handy
kill -9 $(pgrep zproxy)
```