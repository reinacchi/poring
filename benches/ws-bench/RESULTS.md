# ws-bench results

Measured 2026-11-07 on the developer machine (not CI). **One machine, client and server on
the same host, two runs. Read the variance note before comparing numbers.**

- Toolchain: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`; release profile (thin LTO, 16 codegen units).
- Poring: this repository (uncommitted Phase 2–5 work on top of `4046c32`), `default-features = false, features = ["websocket"]`, raw `on_upgrade` echo, 1 MiB message limit, connection/session limits raised to 100 000.
- Axum 0.8.9 (`ws`, `tokio`, `http1`), `WebSocketUpgrade` echo, 1 MiB message limit.
- WebSocket stacks differ by one minor version: Poring uses tokio-tungstenite/tungstenite **0.30.0**, Axum 0.8.9 uses **0.29.0**. Same Tokio and hyper versions (one lockfile).
- Client: tokio-tungstenite 0.30 in a separate process, closed-loop echo of binary messages.
- Run 1: `cargo run --release -- run --secs 3`. Run 2: `cargo run --release -- run --frameworks axum,poring --sizes 64,4096,65536 --conns 1,64 --secs 3` (reversed order).

## Interpretation

- **No winner can be claimed.** Most cells differ by less than the run-to-run variance of the
  *same* framework (15–40 %: e.g. Axum, 1 connection, 64 B measured 31 911 and 45 810 round
  trips/s in the two runs). Differences of that size are noise here.
- The first cell of each run shows a ~2.7 ms handshake for whichever framework runs first
  (Poring in run 1, Axum in run 2): a process/OS warm-up effect, not a framework property.
- With 256 concurrent connects, handshake p99 is ~0.5 s for **both**: the connection burst
  exceeds the listen queue and Windows retries the SYN after ~500 ms. This measures the OS.
- Server CPU and memory are similar (≈9–10 MiB with one session, ≈43–47 MiB at 256 sessions
  with ≤ 16 KiB messages, ≈97–99 MiB at 256 sessions x 64 KiB).
- Not measured: server allocation counts under load (see `tests/tests/ws_alloc.rs` for
  Poring's per-message allocation budget), Linux, TLS, more than 256 connections in this
  harness (see `tests/tests/ws_stress.rs` for 2 000-session correctness), confidence
  intervals over many runs.

## Run 1

- OS: Windows 11 (26300) (x86_64), logical CPUs: 12
- Build: release (thin LTO, 16 CGUs); measure 3 s per cell after 1 s warm-up; client and server on the same machine, separate processes

| framework | conns | size (B) | handshakes/s | hs p50 (us) | hs p99 (us) | round trips/s | MiB/s | p50 (us) | p95 (us) | p99 (us) | server CPU % | server RSS (MiB) | close (ms) | errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| poring | 1 | 64 | 345 | 2823 | 2823 | 46368 | 2.8 | 17 | 39 | 53 | 81 | 9.4 | 0 | 0 |
| poring | 1 | 256 | 1271 | 740 | 740 | 46281 | 11.3 | 17 | 38 | 53 | 80 | 9.6 | 0 | 0 |
| poring | 1 | 1024 | 1293 | 736 | 736 | 39892 | 39.0 | 19 | 46 | 62 | 83 | 9.6 | 0 | 0 |
| poring | 1 | 4096 | 1270 | 739 | 739 | 29560 | 115.5 | 31 | 52 | 64 | 74 | 9.6 | 0 | 0 |
| poring | 1 | 16384 | 1391 | 680 | 680 | 20788 | 324.8 | 44 | 67 | 80 | 67 | 9.7 | 0 | 0 |
| poring | 1 | 65536 | 1334 | 709 | 709 | 11597 | 724.8 | 81 | 106 | 122 | 57 | 9.9 | 0 | 0 |
| poring | 64 | 64 | 12703 | 2839 | 3265 | 87212 | 5.3 | 676 | 1306 | 1760 | 286 | 18.3 | 3 | 0 |
| poring | 64 | 256 | 14698 | 2150 | 2575 | 92579 | 22.6 | 651 | 1150 | 1473 | 294 | 18.3 | 3 | 0 |
| poring | 64 | 1024 | 14162 | 2265 | 2701 | 95209 | 93.0 | 643 | 1097 | 1365 | 251 | 18.2 | 3 | 0 |
| poring | 64 | 4096 | 14600 | 2328 | 2630 | 91414 | 357.1 | 664 | 1158 | 1519 | 337 | 18.7 | 3 | 0 |
| poring | 64 | 16384 | 14510 | 2190 | 2573 | 54891 | 857.7 | 1075 | 2038 | 2955 | 341 | 19.1 | 4 | 0 |
| poring | 64 | 65536 | 13212 | 2395 | 3399 | 19835 | 1239.7 | 3128 | 5648 | 7443 | 318 | 32.8 | 6 | 0 |
| poring | 256 | 64 | 489 | 8639 | 516513 | 46587 | 2.8 | 5233 | 9020 | 11724 | 245 | 42.9 | 13 | 0 |
| poring | 256 | 256 | 479 | 8444 | 517602 | 60337 | 14.7 | 3917 | 7463 | 10665 | 263 | 42.8 | 13 | 0 |
| poring | 256 | 1024 | 477 | 8694 | 518913 | 58231 | 56.9 | 4145 | 7620 | 9497 | 244 | 43.4 | 13 | 0 |
| poring | 256 | 4096 | 491 | 7657 | 514647 | 55465 | 216.7 | 4374 | 7672 | 9810 | 271 | 45.1 | 13 | 0 |
| poring | 256 | 16384 | 492 | 7639 | 513557 | 42745 | 667.9 | 5783 | 9472 | 11565 | 346 | 46.7 | 18 | 0 |
| poring | 256 | 65536 | 489 | 9264 | 515780 | 17451 | 1090.7 | 14392 | 23590 | 29149 | 309 | 97.3 | 23 | 0 |
| axum | 1 | 64 | 1282 | 735 | 735 | 31911 | 1.9 | 29 | 51 | 68 | 71 | 9.5 | 0 | 0 |
| axum | 1 | 256 | 1166 | 806 | 806 | 32062 | 7.8 | 29 | 51 | 67 | 71 | 9.5 | 0 | 0 |
| axum | 1 | 1024 | 1209 | 777 | 777 | 30191 | 29.5 | 29 | 53 | 76 | 74 | 9.5 | 1 | 0 |
| axum | 1 | 4096 | 790 | 1203 | 1203 | 34746 | 135.7 | 24 | 51 | 82 | 74 | 9.4 | 0 | 0 |
| axum | 1 | 16384 | 1349 | 693 | 693 | 26537 | 414.6 | 34 | 57 | 73 | 70 | 9.5 | 0 | 0 |
| axum | 1 | 65536 | 1413 | 664 | 664 | 13907 | 869.2 | 66 | 95 | 122 | 60 | 9.7 | 0 | 0 |
| axum | 64 | 64 | 12229 | 2758 | 3037 | 75461 | 4.6 | 713 | 1750 | 3061 | 278 | 18.1 | 3 | 0 |
| axum | 64 | 256 | 14894 | 2135 | 2987 | 103816 | 25.3 | 576 | 1069 | 1400 | 308 | 18.3 | 4 | 0 |
| axum | 64 | 1024 | 10746 | 3138 | 3969 | 104226 | 101.8 | 581 | 1040 | 1325 | 307 | 18.4 | 3 | 0 |
| axum | 64 | 4096 | 13992 | 2377 | 2657 | 91502 | 357.4 | 641 | 1250 | 1832 | 295 | 18.8 | 4 | 0 |
| axum | 64 | 16384 | 8309 | 3926 | 6817 | 59927 | 936.4 | 1004 | 1845 | 2466 | 293 | 19.6 | 4 | 0 |
| axum | 64 | 65536 | 12715 | 2707 | 3198 | 18929 | 1183.1 | 3235 | 5624 | 7502 | 317 | 31.9 | 6 | 0 |
| axum | 256 | 64 | 496 | 7715 | 509773 | 52086 | 3.2 | 4742 | 7835 | 9519 | 290 | 43.2 | 12 | 0 |
| axum | 256 | 256 | 486 | 7525 | 510079 | 70509 | 17.2 | 3379 | 6501 | 8235 | 324 | 42.4 | 14 | 0 |
| axum | 256 | 1024 | 484 | 8344 | 512358 | 61297 | 59.9 | 3934 | 7265 | 9119 | 246 | 43.4 | 12 | 0 |
| axum | 256 | 4096 | 494 | 8245 | 510549 | 57586 | 224.9 | 4293 | 7116 | 8546 | 281 | 43.8 | 12 | 0 |
| axum | 256 | 16384 | 477 | 8751 | 531171 | 43137 | 674.0 | 5751 | 9386 | 11256 | 302 | 47.0 | 15 | 0 |
| axum | 256 | 65536 | 492 | 8465 | 514288 | 17052 | 1065.8 | 14557 | 24684 | 30561 | 312 | 99.3 | 24 | 0 |

## Run 2 (reversed order, reduced matrix)

| framework | conns | size (B) | handshakes/s | hs p50 (us) | hs p99 (us) | round trips/s | MiB/s | p50 (us) | p95 (us) | p99 (us) | server CPU % | server RSS (MiB) | close (ms) | errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| axum | 1 | 64 | 365 | 2673 | 2673 | 45810 | 2.8 | 17 | 39 | 55 | 78 | 9.1 | 0 | 0 |
| axum | 1 | 4096 | 1362 | 699 | 699 | 36469 | 142.5 | 21 | 50 | 66 | 77 | 9.5 | 0 | 0 |
| axum | 1 | 65536 | 1302 | 731 | 731 | 13064 | 816.5 | 71 | 101 | 125 | 56 | 9.7 | 0 | 0 |
| axum | 64 | 64 | 12097 | 2930 | 3548 | 94956 | 5.8 | 622 | 1209 | 1618 | 289 | 18.0 | 3 | 0 |
| axum | 64 | 4096 | 13262 | 2662 | 3191 | 77397 | 302.3 | 776 | 1421 | 1886 | 280 | 19.0 | 3 | 0 |
| axum | 64 | 65536 | 12793 | 2384 | 3177 | 18872 | 1179.5 | 3233 | 5669 | 7480 | 284 | 32.5 | 6 | 0 |
| poring | 1 | 64 | 1021 | 942 | 942 | 42263 | 2.6 | 18 | 44 | 58 | 76 | 9.7 | 0 | 0 |
| poring | 1 | 4096 | 1415 | 670 | 670 | 37632 | 147.0 | 21 | 47 | 63 | 80 | 9.6 | 0 | 0 |
| poring | 1 | 65536 | 1149 | 830 | 830 | 13043 | 815.2 | 71 | 101 | 123 | 60 | 9.9 | 0 | 0 |
| poring | 64 | 64 | 11190 | 3151 | 3745 | 103171 | 6.3 | 579 | 1095 | 1416 | 321 | 18.2 | 3 | 0 |
| poring | 64 | 4096 | 11664 | 2991 | 3387 | 92141 | 359.9 | 657 | 1173 | 1501 | 314 | 18.6 | 3 | 0 |
| poring | 64 | 65536 | 12243 | 2822 | 3309 | 19450 | 1215.6 | 3168 | 5442 | 7134 | 332 | 32.2 | 5 | 0 |
