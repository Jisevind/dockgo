# [0.3.0](https://github.com/Jisevind/dockgo/compare/v0.2.1...v0.3.0) (2026-02-24)


### Bug Fixes

* **api:** strengthen container name validation ([f13209f](https://github.com/Jisevind/dockgo/commit/f13209fb0c3c6d6ec0e30b77c5b6d95697c594e5))
* **auth:** use crypto/rand for secret generation ([d71e8bb](https://github.com/Jisevind/dockgo/commit/d71e8bbde896ba763b7028edc7ffb998c683b671))
* **engine:** fallback to standalone api on compose failure ([ce1322f](https://github.com/Jisevind/dockgo/commit/ce1322f68ac2e714991c70cf354fe06f2444c09c))
* **engine:** handle platform-specific digest caching ([8521d84](https://github.com/Jisevind/dockgo/commit/8521d8473892b68320cb823ede9184e7d9cff6bb))
* **engine:** skip containers with empty names ([767b9b2](https://github.com/Jisevind/dockgo/commit/767b9b2aa727d2a029868d4f61c8051124494578))
* **notify:** add error handling for crypto/rand operations ([b19172e](https://github.com/Jisevind/dockgo/commit/b19172ed1edae5a4932a0d62e6c7c153a8b8120b))
* **notify:** replace math/rand with crypto/rand for jitter calculation ([5f8568f](https://github.com/Jisevind/dockgo/commit/5f8568f6972acbba21025d4c800ea7778a88e7e8))
* **notify:** safely drain queue without closing channel during shutdown ([d65d8bf](https://github.com/Jisevind/dockgo/commit/d65d8bfe304acf6b5a13ea75caceae8686bfc39e))
* **server:** add periodic cleanup of rate limiters ([d1f371b](https://github.com/Jisevind/dockgo/commit/d1f371b3c5a35d0b1bd18b1d5883f8400535516e))
* **server:** properly marshal JSON in SSE responses ([6d905ca](https://github.com/Jisevind/dockgo/commit/6d905ca35847999d362cbf906fe6bf5cb2614279))
* **server:** validate CORS origin with scheme and host ([3a640eb](https://github.com/Jisevind/dockgo/commit/3a640ebaef093551fafbf3864428f0a4909c0b66))
* **updater:** prevent unsafe fallback for orchestrated containers ([67f87b7](https://github.com/Jisevind/dockgo/commit/67f87b72ce285589d3277a3762b6a199ef82ee2d))


### Features

* **auth:** add bcrypt password hash support and CLI generator ([10ce7d0](https://github.com/Jisevind/dockgo/commit/10ce7d0e205e95738a84b3ea52e452322004b03e))
* **auth:** add CSRF protection and session revocation ([1fb8af7](https://github.com/Jisevind/dockgo/commit/1fb8af7b427f48af532a1ad3080698c31d716d57))
* **auth:** add persistent session storage ([d4f5d0e](https://github.com/Jisevind/dockgo/commit/d4f5d0e2ebdd93c4f14dbebee05765bd46bb41fd))
* **cli:** default to serve when no command provided ([498d307](https://github.com/Jisevind/dockgo/commit/498d307765bb1541ce0c652a7950f8bcfcc0c8f0))
* **engine:** add progress callback and improve compose output formatting ([86a0766](https://github.com/Jisevind/dockgo/commit/86a07662634016354e212d675253ea8069bbfdf8))
* restrict compose working directories to allowed paths ([7b97f71](https://github.com/Jisevind/dockgo/commit/7b97f71ddc74fd0aaacab9a9cd06f514187641d6))
* **scanner:** add platform detection for container images ([219ea2f](https://github.com/Jisevind/dockgo/commit/219ea2fe6ef5cc35e655c84e6590275d455eb377))
* **server:** configure http server timeouts ([b43477c](https://github.com/Jisevind/dockgo/commit/b43477cb8e05defcdb73316692489f301da7993d))
* **server:** improve cors origin validation ([6b4ea1f](https://github.com/Jisevind/dockgo/commit/6b4ea1fb38c2fdd79da60efe97a7200577dd1d91))


### Performance Improvements

* **auth:** debounce session persistence writes ([635e26c](https://github.com/Jisevind/dockgo/commit/635e26c317f2f08894731db148fcd1a4889465e3))

## [0.2.1](https://github.com/Jisevind/dockgo/compare/v0.2.0...v0.2.1) (2026-02-22)


### Bug Fixes

* trigger docker release pipeline ([ff94b31](https://github.com/Jisevind/dockgo/commit/ff94b31374cca23e37d22e489475d03281a4d632))

# [0.2.0](https://github.com/Jisevind/dockgo/compare/v0.1.0...v0.2.0) (2026-02-22)


### Bug Fixes

* **auth:** prevent container fetch when not authenticated ([2bb4eb3](https://github.com/Jisevind/dockgo/commit/2bb4eb34cc3642f4842d1dcc89d3cfc2db8515fa))
* improve update cache and readiness checks ([6249957](https://github.com/Jisevind/dockgo/commit/6249957833ecfb550dd94788242a1a38559b429f))
* **notify:** improve apprise reliability and config ([73d821a](https://github.com/Jisevind/dockgo/commit/73d821ab13b6007ff05f2b6eadb645ad11151302))
* **notify:** prevent duplicate notify path in apprise url ([96f8be4](https://github.com/Jisevind/dockgo/commit/96f8be4f5ed0336111139c7ecd3424037a8a0b4a))
* **notify:** prevent race condition in apprise notify queue ([20bc282](https://github.com/Jisevind/dockgo/commit/20bc282325660ffc08d9e21a360bf0551de10a5a))


### Features

* **notify:** add apprise notification support ([34787dc](https://github.com/Jisevind/dockgo/commit/34787dcbbbdeeed2d29602423288748076960086))
* **notify:** add graceful shutdown and retry logic to apprise ([3eea6b5](https://github.com/Jisevind/dockgo/commit/3eea6b5013b48836422322053a556d2830919409))
* **notify:** consolidate update notifications ([8bf2b07](https://github.com/Jisevind/dockgo/commit/8bf2b07c39ee3915896fbc8681938c28be55d856))
* **notify:** make apprise queue size configurable ([2a18f1d](https://github.com/Jisevind/dockgo/commit/2a18f1d766f0592c63f80f6c775122dd66def289))
* **registry:** add force refresh option to bypass cache ([0e9b36f](https://github.com/Jisevind/dockgo/commit/0e9b36f9d8e2a51aadc95776a7a5bf016bde87a2))
* **server:** hide temporary update containers ([9793a87](https://github.com/Jisevind/dockgo/commit/9793a8762b57688d689c55c0c48c88b776f1d697))
* **update:** add configurable background update scheduler ([4b4a696](https://github.com/Jisevind/dockgo/commit/4b4a69615f168fe50a75f43876ea667201dbdbcc))
