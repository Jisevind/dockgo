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
