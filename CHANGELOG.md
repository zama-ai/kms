# KMS Changelog

# [0.8.0](https://github.com/zama-ai/kms-core/compare/v0.7.1...v0.8.0) (2024-07-19)


### Bug Fixes

* Add dashmap and retrying dependencies ([#860](https://github.com/zama-ai/kms-core/issues/860)) ([0f109f9](https://github.com/zama-ai/kms-core/commit/0f109f9251c8a7ecf6db88917a2344b35531f28a))
* bump versions and move some to workspace ([#814](https://github.com/zama-ai/kms-core/issues/814)) ([8921c44](https://github.com/zama-ai/kms-core/commit/8921c44fd2104175ff5f0dcc07f96b23f96c1c70))
* change sha3 to shake256 for H_AR according to NIST spec ([#816](https://github.com/zama-ai/kms-core/issues/816)) ([c794d09](https://github.com/zama-ai/kms-core/commit/c794d0965698e72cc85610f8bd96c9b3d795f764))
* ci and bump versions ([#800](https://github.com/zama-ai/kms-core/issues/800)) ([4d33477](https://github.com/zama-ai/kms-core/commit/4d33477dc50be6d5e9a4d9b5e5e52426e31177e5))
* File storage purge should not fail if directory is not found ([#844](https://github.com/zama-ai/kms-core/issues/844)) ([d2cff84](https://github.com/zama-ai/kms-core/commit/d2cff8473abdf8d122719a328d57ed08b1b12e29))
* Make S3 proxy setting optional outside of the enclave ([#845](https://github.com/zama-ai/kms-core/issues/845)) ([951767d](https://github.com/zama-ai/kms-core/commit/951767dd8b2a8c825b9c7e5f868e079ab808ccd6))
* relative filepath parsing in kms-gen-keys ([#858](https://github.com/zama-ai/kms-core/issues/858)) ([6c87cee](https://github.com/zama-ai/kms-core/commit/6c87ceefd0e2811654820f440d63d327594f9e43))
* StorageReader::all_urls() behaviour with empty S3 buckets ([#859](https://github.com/zama-ai/kms-core/issues/859)) ([6e058c8](https://github.com/zama-ai/kms-core/commit/6e058c8e452abd9d0c2202486a713252ed7a3b5c))


### Features

* Add versioning compatibility with structs stored ([#743](https://github.com/zama-ai/kms-core/issues/743)) ([aac6fba](https://github.com/zama-ai/kms-core/commit/aac6fba04cb1eb2f2677e6c56e6e14e932ccac11))
* adding support for generate release from branch, tag or SHA ([9f0a558](https://github.com/zama-ai/kms-core/commit/9f0a558095ea45c2f823bde766eb467f22342504))
* **gateway:** threshold decryption majority vote ([#839](https://github.com/zama-ai/kms-core/issues/839)) ([eff4d74](https://github.com/zama-ai/kms-core/commit/eff4d74efc4c8230bfb5502cbc373faeee56bcfd))
* Granular selection of storage backends ([#761](https://github.com/zama-ai/kms-core/issues/761)) ([a539bf6](https://github.com/zama-ai/kms-core/commit/a539bf62c272e02f1c54dfad9d0f22525c7d5e5b))
* implement distributing tracing ([#802](https://github.com/zama-ai/kms-core/issues/802)) ([3a1dc8e](https://github.com/zama-ai/kms-core/commit/3a1dc8eefc2f8fc6620fa411ed8834df19ae44b1))
* **network:** Clear Async/Sync distinction + make send non-blocking from Party pov ([#710](https://github.com/zama-ai/kms-core/issues/710)) ([9708936](https://github.com/zama-ai/kms-core/commit/9708936e7b476447321526b5179493a394765153))

## [0.7.1](https://github.com/zama-ai/kms-core/compare/v0.7.0...v0.7.1) (2024-07-02)


### Bug Fixes

* merge issue ([73454b4](https://github.com/zama-ai/kms-core/commit/73454b4e14033399906e71b4b7d3ef1fa24f9943))

# [0.7.0](https://github.com/zama-ai/kms-core/compare/v0.6.0...v0.7.0) (2024-06-30)


### Features

* Update gas limit and gas escalator increase in GatewayConfig ([2fd5310](https://github.com/zama-ai/kms-core/commit/2fd5310530f42d5dab75791ffa0587d46a3df599))

# [0.6.0](https://github.com/zama-ai/kms-core/compare/v0.5.0...v0.6.0) (2024-06-30)


### Features

* **gateway:** Add support for concurrent ciphertext decryptions ([81dedb2](https://github.com/zama-ai/kms-core/commit/81dedb2215ba0f78038bea4ebf1cc24977c4c88b))

# [0.5.0](https://github.com/zama-ai/kms-core/compare/v0.4.6...v0.5.0) (2024-06-30)


### Features

* Update coprocessor URL in GatewayConfig, extra logging for ebytes256, added gas escalation logic addressing mempool locks ([402ff61](https://github.com/zama-ai/kms-core/commit/402ff61edcedbf2e1e30d1794d582752ab650335))

## [0.4.6](https://github.com/zama-ai/kms-core/compare/v0.4.5...v0.4.6) (2024-06-29)


### Bug Fixes

* Add chain ID to reencryption request and update gateway configur… ([#791](https://github.com/zama-ai/kms-core/issues/791)) ([fb10760](https://github.com/zama-ai/kms-core/commit/fb107604b190051de31dea4987136779a6436892))
* updated reenc tests and endianness in chain_id ([#792](https://github.com/zama-ai/kms-core/issues/792)) ([24f35a5](https://github.com/zama-ai/kms-core/commit/24f35a53869e599d274e74a8b254a90cd585178e))

## [0.4.5](https://github.com/zama-ai/kms-core/compare/v0.4.4...v0.4.5) (2024-06-28)


### Bug Fixes

* ci ([#788](https://github.com/zama-ai/kms-core/issues/788)) ([a0844f7](https://github.com/zama-ai/kms-core/commit/a0844f7cb3f6c8c9e7fd51831847f6c72ca3c137))

## [0.4.4](https://github.com/zama-ai/kms-core/compare/v0.4.3...v0.4.4) (2024-06-28)


### Bug Fixes

* ci ([#787](https://github.com/zama-ai/kms-core/issues/787)) ([19f754d](https://github.com/zama-ai/kms-core/commit/19f754d36090922bc40a9d407ad578157a74fa22))

## [0.4.3](https://github.com/zama-ai/kms-core/compare/v0.4.2...v0.4.3) (2024-06-28)


### Bug Fixes

* ci ([#786](https://github.com/zama-ai/kms-core/issues/786)) ([e00c5c8](https://github.com/zama-ai/kms-core/commit/e00c5c8c2e7659d4476a0aa621b75b97be06cd01))

## [0.4.2](https://github.com/zama-ai/kms-core/compare/v0.4.1...v0.4.2) (2024-06-28)


### Bug Fixes

* adding doc ([#784](https://github.com/zama-ai/kms-core/issues/784)) ([c2569b3](https://github.com/zama-ai/kms-core/commit/c2569b33133489bc8855906062aa8f5cbfb88aba))
* small fix on pipeline ([#783](https://github.com/zama-ai/kms-core/issues/783)) ([173ab58](https://github.com/zama-ai/kms-core/commit/173ab5887b3874c2c4b87937cd7bfcc84b6342f6))
* update Cargo.lock ([#785](https://github.com/zama-ai/kms-core/issues/785)) ([ba9ec8b](https://github.com/zama-ai/kms-core/commit/ba9ec8b3b330b084e7f9d82a6a344863455c9e9f))

## [0.4.1](https://github.com/zama-ai/kms-core/compare/v0.4.0...v0.4.1) (2024-06-28)


### Bug Fixes

* add cargo version bump ([#782](https://github.com/zama-ai/kms-core/issues/782)) ([d1e359e](https://github.com/zama-ai/kms-core/commit/d1e359ec6108ccd982d8489da59dcfba63ba7d06))

# [0.4.0](https://github.com/zama-ai/kms-core/compare/v0.3.2...v0.4.0) (2024-06-28)


### Bug Fixes

* add gateway docker compose ([#700](https://github.com/zama-ai/kms-core/issues/700)) ([092937e](https://github.com/zama-ai/kms-core/commit/092937ea77cde5c51ef2bea66db0117e36d09363))
* add health check ([#691](https://github.com/zama-ai/kms-core/issues/691)) ([9c2ccbe](https://github.com/zama-ai/kms-core/commit/9c2ccbeb67b10e6fbf089ae6a7f5badd1a57800a))
* added missing format! macros for error messages ([#569](https://github.com/zama-ai/kms-core/issues/569)) ([9aef30e](https://github.com/zama-ai/kms-core/commit/9aef30e658043381df308c2c83f6349231a160af))
* adding connector config logs ([#667](https://github.com/zama-ai/kms-core/issues/667)) ([1c346a8](https://github.com/zama-ai/kms-core/commit/1c346a80a67be7453c7d265dd07c40908aa109c8))
* adding dep ci pipelines ([#591](https://github.com/zama-ai/kms-core/issues/591)) ([8b87bc2](https://github.com/zama-ai/kms-core/commit/8b87bc2c84f3983d68457dae8d4e92804c8f95d9))
* again ([#754](https://github.com/zama-ai/kms-core/issues/754)) ([a098636](https://github.com/zama-ai/kms-core/commit/a098636fa503c8989e5b87fbdecf6f6dae36fbf1))
* again ([#755](https://github.com/zama-ai/kms-core/issues/755)) ([9bbdb95](https://github.com/zama-ai/kms-core/commit/9bbdb95e031f5b2fbfc8e30218945be756eece94))
* again ([#756](https://github.com/zama-ai/kms-core/issues/756)) ([50872c4](https://github.com/zama-ai/kms-core/commit/50872c402c9b9f070ccac373fae937fc1c8f2213))
* bgv benchmarks ([#387](https://github.com/zama-ai/kms-core/issues/387)) ([9ec2557](https://github.com/zama-ai/kms-core/commit/9ec255750a25eea781eb2bd08182efd9831a46ad))
* **blockchain:** added additional proof type variable to contract ins… ([#533](https://github.com/zama-ai/kms-core/issues/533)) ([066a2ef](https://github.com/zama-ai/kms-core/commit/066a2efab69d43780e35fe10463444a09deee332))
* **blockchain:** fixed typo in docker-compose ([1c0478d](https://github.com/zama-ai/kms-core/commit/1c0478d325fe6a9dd0172e41d435f2559e7eb5c7))
* bump versions ([#509](https://github.com/zama-ai/kms-core/issues/509)) ([9cef76f](https://github.com/zama-ai/kms-core/commit/9cef76f32ed201dbab9d8ebd6e6b0e3cf95c434b))
* **ceremony:** accidently erase tau in ceremony ([#541](https://github.com/zama-ai/kms-core/issues/541)) ([179b80a](https://github.com/zama-ai/kms-core/commit/179b80ad427095a90ce0a021e4d283b46361dd01))
* change ami ([#681](https://github.com/zama-ai/kms-core/issues/681)) ([03a24c3](https://github.com/zama-ai/kms-core/commit/03a24c34c7f9ed271bb2f6220db4594bf7959d2d))
* ci  ([#723](https://github.com/zama-ai/kms-core/issues/723)) ([2c56c41](https://github.com/zama-ai/kms-core/commit/2c56c4148b6da54b4df11a3ca4a60a63bb332562))
* ci ([#717](https://github.com/zama-ai/kms-core/issues/717)) ([173828c](https://github.com/zama-ai/kms-core/commit/173828ca534a8edfbd3c94b2b2b0ad43c45d3263))
* ci ([#718](https://github.com/zama-ai/kms-core/issues/718)) ([5489c87](https://github.com/zama-ai/kms-core/commit/5489c87a9a1c7cbba9cef574e5f31413e4e30b86))
* ci ([#719](https://github.com/zama-ai/kms-core/issues/719)) ([23b5fe9](https://github.com/zama-ai/kms-core/commit/23b5fe9264154354c7fb9e2f5503cbcbc64f4cac))
* ci ([#720](https://github.com/zama-ai/kms-core/issues/720)) ([4e7d708](https://github.com/zama-ai/kms-core/commit/4e7d708d62a49c81799df0f327325a7d21dbe463))
* ci ([#721](https://github.com/zama-ai/kms-core/issues/721)) ([fe99f8c](https://github.com/zama-ai/kms-core/commit/fe99f8cbc337b54b4cecd7deab16c5839c1a48d1))
* ci ([#722](https://github.com/zama-ai/kms-core/issues/722)) ([269ca62](https://github.com/zama-ai/kms-core/commit/269ca62ce0a0e8bcdabf1e1256af8bab1c05bbff))
* ci ([#724](https://github.com/zama-ai/kms-core/issues/724)) ([50c9664](https://github.com/zama-ai/kms-core/commit/50c966439d6c06ce0fe71c00d4badf8415a8288d))
* ci ([#725](https://github.com/zama-ai/kms-core/issues/725)) ([8b6fefb](https://github.com/zama-ai/kms-core/commit/8b6fefb55c5520d518eb441fda11234464bb5e96))
* ci ([#726](https://github.com/zama-ai/kms-core/issues/726)) ([29b731f](https://github.com/zama-ai/kms-core/commit/29b731feb70ef02ffab76345a37af0dc48197739))
* ci ([#727](https://github.com/zama-ai/kms-core/issues/727)) ([aa9971e](https://github.com/zama-ai/kms-core/commit/aa9971e987124e3de70b3bc784557304b24cab0c))
* ci ([#762](https://github.com/zama-ai/kms-core/issues/762)) ([ff7e758](https://github.com/zama-ai/kms-core/commit/ff7e7586f6cf1cc0cdb0cbfdb82a612fc9a04bfc))
* ci ([#763](https://github.com/zama-ai/kms-core/issues/763)) ([b5a0763](https://github.com/zama-ai/kms-core/commit/b5a07630e7078379a71dd5121327c3817f7507f0))
* ci ([#764](https://github.com/zama-ai/kms-core/issues/764)) ([856a524](https://github.com/zama-ai/kms-core/commit/856a5247c869b822d0b2a79212cf8d0303d0ef23))
* ci ([#765](https://github.com/zama-ai/kms-core/issues/765)) ([8cd13ef](https://github.com/zama-ai/kms-core/commit/8cd13efdaec6aa2330603828df61305b9b163d7b))
* ci ([#766](https://github.com/zama-ai/kms-core/issues/766)) ([4f9392b](https://github.com/zama-ai/kms-core/commit/4f9392b30c1193379dfd30540d4d0226d05619ed))
* ci ([#767](https://github.com/zama-ai/kms-core/issues/767)) ([961c636](https://github.com/zama-ai/kms-core/commit/961c636fc3f4be19cad80f5c2cc6102fc6345a3a))
* ci ([#768](https://github.com/zama-ai/kms-core/issues/768)) ([f94f538](https://github.com/zama-ai/kms-core/commit/f94f538fdafb49e19d006f4ae792a7227aa280a0))
* ci ([#769](https://github.com/zama-ai/kms-core/issues/769)) ([665bc6a](https://github.com/zama-ai/kms-core/commit/665bc6aaa90eeaacce3c3f5a2c79e3791599fc8f))
* ci ([#770](https://github.com/zama-ai/kms-core/issues/770)) ([65e522b](https://github.com/zama-ai/kms-core/commit/65e522b84879eedb56d71a4d8136838a250a1c4e))
* ci ([#771](https://github.com/zama-ai/kms-core/issues/771)) ([a7b6aa7](https://github.com/zama-ai/kms-core/commit/a7b6aa7334c7031beeadd8463d17d7090f5531e5))
* ci ([#772](https://github.com/zama-ai/kms-core/issues/772)) ([86113ae](https://github.com/zama-ai/kms-core/commit/86113ae50f92e212ba97dd2cd5600359f1c09894))
* ci ([#775](https://github.com/zama-ai/kms-core/issues/775)) ([326dfcd](https://github.com/zama-ai/kms-core/commit/326dfcd3f6765797ebeb0d5609d2e1be211a74ab))
* ci ([#776](https://github.com/zama-ai/kms-core/issues/776)) ([1a8622c](https://github.com/zama-ai/kms-core/commit/1a8622ca6bb51c8431d88cfb7b723bac3432207a))
* ci ([#777](https://github.com/zama-ai/kms-core/issues/777)) ([d007093](https://github.com/zama-ai/kms-core/commit/d00709389d1997b8afa8aab0120c52bcef2a5fa5))
* ci ([#778](https://github.com/zama-ai/kms-core/issues/778)) ([44d9cf0](https://github.com/zama-ai/kms-core/commit/44d9cf0ee6d4ae12de0693c4e831f16007cf70d7))
* ci ([#779](https://github.com/zama-ai/kms-core/issues/779)) ([2ceda0a](https://github.com/zama-ai/kms-core/commit/2ceda0a3a557df7018d3db36a31f3f63671aff38))
* ci ([#780](https://github.com/zama-ai/kms-core/issues/780)) ([9fbd06b](https://github.com/zama-ai/kms-core/commit/9fbd06b737dc2394149ae80798a658726ffae802))
* ci ([#781](https://github.com/zama-ai/kms-core/issues/781)) ([bcbf4f5](https://github.com/zama-ai/kms-core/commit/bcbf4f5ce73aab2d63937182d948117bb4a1a644))
* ci cd ami updated for big instances ([#411](https://github.com/zama-ai/kms-core/issues/411)) ([87675e7](https://github.com/zama-ai/kms-core/commit/87675e78719e780f843f0bbfdc2a63224c41f065))
* ci pipeline ([#671](https://github.com/zama-ai/kms-core/issues/671)) ([7476657](https://github.com/zama-ai/kms-core/commit/747665759a58a1f02fd2af61482fcd902de51f6b))
* ci pipeline ([#672](https://github.com/zama-ai/kms-core/issues/672)) ([61fd05f](https://github.com/zama-ai/kms-core/commit/61fd05f4a48677b9c5ea0c43d22caefe0821e4ed))
* ci pipeline ([#673](https://github.com/zama-ai/kms-core/issues/673)) ([56b786a](https://github.com/zama-ai/kms-core/commit/56b786af848143ecdd8f951176d2f851c5cfe6d4))
* CI that was not running tests ([#114](https://github.com/zama-ai/kms-core/issues/114)) ([5d760a6](https://github.com/zama-ai/kms-core/commit/5d760a6c93ac14cee1852d3e6f4653d61c00da84))
* **ci:** generate-image-dev -> generate-dev-image ([#696](https://github.com/zama-ai/kms-core/issues/696)) ([cb8e8ad](https://github.com/zama-ai/kms-core/commit/cb8e8ad724bb12dad1425a90521755bde8823ff7))
* connector error ([#634](https://github.com/zama-ai/kms-core/issues/634)) ([ead54fc](https://github.com/zama-ai/kms-core/commit/ead54fcbdd146daa5ebad791e61554d1c3d47387))
* connector error ([#637](https://github.com/zama-ai/kms-core/issues/637)) ([2252bea](https://github.com/zama-ai/kms-core/commit/2252beaca5513e3fd059de76b4eec14caa368714))
* **connector:** connector tests did not assert response length ([#503](https://github.com/zama-ai/kms-core/issues/503)) ([eac10fd](https://github.com/zama-ai/kms-core/commit/eac10fde4090367c36b97166633ae91263ba8672))
* **connector:** integration test ([#524](https://github.com/zama-ai/kms-core/issues/524)) ([840c9ae](https://github.com/zama-ai/kms-core/commit/840c9ae816c5814ee5a7a7adb7cffc626799a03e))
* **connector:** slow tests that were not running on CI ([#649](https://github.com/zama-ai/kms-core/issues/649)) ([fb69680](https://github.com/zama-ai/kms-core/commit/fb69680b389a73a8defefea9acff52206deb32c9))
* **coordinator:** take request_id out of reenc payload ([#511](https://github.com/zama-ai/kms-core/issues/511)) ([4a4b733](https://github.com/zama-ai/kms-core/commit/4a4b73383d2d13cbfe8385d34f4c8771896c4570))
* **core:** add domain separation ([#692](https://github.com/zama-ai/kms-core/issues/692)) ([32582e3](https://github.com/zama-ai/kms-core/commit/32582e347efbbab87ab62fd9700bd001864da14f)), closes [#626](https://github.com/zama-ai/kms-core/issues/626)
* **core:** allow decryption/reencryption for up to u160 ([#636](https://github.com/zama-ai/kms-core/issues/636)) ([7aa9a11](https://github.com/zama-ai/kms-core/commit/7aa9a112e471b5ade96cb19b4a7c659df63f2fac))
* **core:** long locks in ddec/reenc; add parallel tests ([#644](https://github.com/zama-ai/kms-core/issues/644)) ([656c352](https://github.com/zama-ai/kms-core/commit/656c3523811fb15e9570a1fcc1e826878af56994))
* **core:** make sure the solidity type name matches fhevmjs ([#757](https://github.com/zama-ai/kms-core/issues/757)) ([aa90d98](https://github.com/zama-ai/kms-core/commit/aa90d986d19df7ffb61557d9c4ad372101d82a14))
* **core:** test failure caused by missing testing feature ([#662](https://github.com/zama-ai/kms-core/issues/662)) ([8d5ee0d](https://github.com/zama-ai/kms-core/commit/8d5ee0d3d80111208a11fb901137b86b230abe16))
* **core:** use lock().await instead of try_lock for rng ([#656](https://github.com/zama-ai/kms-core/issues/656)) ([319b2e5](https://github.com/zama-ai/kms-core/commit/319b2e54a63cd6a542712a3058d598227e865b9d))
* dev image ([#674](https://github.com/zama-ai/kms-core/issues/674)) ([737209d](https://github.com/zama-ai/kms-core/commit/737209d885ad074e573777c85d3b8ce07f9b207f))
* dev image generation and graviton instance ([#684](https://github.com/zama-ai/kms-core/issues/684)) ([560dc44](https://github.com/zama-ai/kms-core/commit/560dc44b6219e23d0d60cea59e200e9913ba63b4))
* do not panic when wrong client key is used ([#107](https://github.com/zama-ai/kms-core/issues/107)) ([70d9756](https://github.com/zama-ai/kms-core/commit/70d9756e1f338b2cf246e7db67f852e14de018d2))
* docker compose ([#497](https://github.com/zama-ai/kms-core/issues/497)) ([ed6f799](https://github.com/zama-ai/kms-core/commit/ed6f799284f2515469f29f88bf1be093396b56c4))
* docker image ([#676](https://github.com/zama-ai/kms-core/issues/676)) ([08d21f0](https://github.com/zama-ai/kms-core/commit/08d21f095e3e76fc0f3a0dd269bddebd54ec190c))
* docker image ([#677](https://github.com/zama-ai/kms-core/issues/677)) ([96513c9](https://github.com/zama-ai/kms-core/commit/96513c956da240705fe5ba37d45e92ab5c7690ba))
* docker image ([#678](https://github.com/zama-ai/kms-core/issues/678)) ([9c7c933](https://github.com/zama-ai/kms-core/commit/9c7c9337da4bb5aa7a5525ee8a474cf4ec768311))
* docker image ([#679](https://github.com/zama-ai/kms-core/issues/679)) ([e82643f](https://github.com/zama-ai/kms-core/commit/e82643fdbd22123d512929a004811b34af1168b8))
* docker image ([#689](https://github.com/zama-ai/kms-core/issues/689)) ([b6e1d10](https://github.com/zama-ai/kms-core/commit/b6e1d101d4b9dd8bee5ebd92abe24a9390a60974))
* docker images ([#694](https://github.com/zama-ai/kms-core/issues/694)) ([0d425cc](https://github.com/zama-ai/kms-core/commit/0d425cc8082b70c78cdba35b22d030061828ac9c))
* dockerfile ([#466](https://github.com/zama-ai/kms-core/issues/466)) ([6841a2e](https://github.com/zama-ai/kms-core/commit/6841a2efd8ea5ebb9b604683323b85e4becffdc9))
* docs ([#368](https://github.com/zama-ai/kms-core/issues/368)) ([d5b1dbc](https://github.com/zama-ai/kms-core/commit/d5b1dbc4b8de6fe4cafde07754481f9c42f52c1f))
* fix dev image ([#668](https://github.com/zama-ai/kms-core/issues/668)) ([40cfc7f](https://github.com/zama-ai/kms-core/commit/40cfc7f79162763f6bc9ac6ec37fb3336329dca5))
* fix dev image ([#669](https://github.com/zama-ai/kms-core/issues/669)) ([3ad12de](https://github.com/zama-ai/kms-core/commit/3ad12de0f1ade402a4a8d474e780865d4c8fb986))
* fix docker compose ([#670](https://github.com/zama-ai/kms-core/issues/670)) ([cf39a36](https://github.com/zama-ai/kms-core/commit/cf39a3654d0536503e912d5c0a352b58f1b1bb11))
* Fixing breaking lints for upgrading rustc compiler to 1.76 ([#342](https://github.com/zama-ai/kms-core/issues/342)) ([14f753e](https://github.com/zama-ai/kms-core/commit/14f753e4ef033ec3447156fdb93ed0bb0fbd9819))
* force ci ([#712](https://github.com/zama-ai/kms-core/issues/712)) ([b72c478](https://github.com/zama-ai/kms-core/commit/b72c478b85d6369cd3b864ebc92925027453c400))
* force ci ([#716](https://github.com/zama-ai/kms-core/issues/716)) ([1e9c938](https://github.com/zama-ai/kms-core/commit/1e9c9385de9cbd89eeb9ca8c3b6b18c1eb7ffe2a))
* **gateway:** fixed formatting problem with eaddress ([#748](https://github.com/zama-ai/kms-core/issues/748)) ([0ee8f13](https://github.com/zama-ai/kms-core/commit/0ee8f139746ebfb27d8b843f01634ae4a3f4666a))
* **gateway:** mnemonic test ([#741](https://github.com/zama-ai/kms-core/issues/741)) ([6563b65](https://github.com/zama-ai/kms-core/commit/6563b658281e55411db96affb71de1742ba340e5))
* generate default CRS only in slow tests, fix tests without CRS ([#105](https://github.com/zama-ai/kms-core/issues/105)) ([c4c2f9b](https://github.com/zama-ai/kms-core/commit/c4c2f9b604a87e2651be98475bc2935bee8a1c23))
* increase_round_counter does not neet do be async [#246](https://github.com/zama-ai/kms-core/issues/246) ([#369](https://github.com/zama-ai/kms-core/issues/369)) ([6892d30](https://github.com/zama-ai/kms-core/commit/6892d302f8c1c8d6630ca163132293cc3248ffa2))
* issue toolchain for doc ([#365](https://github.com/zama-ai/kms-core/issues/365)) ([68cc4b1](https://github.com/zama-ai/kms-core/commit/68cc4b1de2af87e8ac65480bf38ca2ff4d07d5c5))
* issue workflow ([#364](https://github.com/zama-ai/kms-core/issues/364)) ([4f1fd47](https://github.com/zama-ai/kms-core/commit/4f1fd473d974e1e96d767c94e647a60287557b55))
* make docker work again ([#443](https://github.com/zama-ai/kms-core/issues/443)) ([b312a9e](https://github.com/zama-ai/kms-core/commit/b312a9e9029d95d22a8d143c5281c13e116dad6a))
* manual workflow ([#685](https://github.com/zama-ai/kms-core/issues/685)) ([63fd2d5](https://github.com/zama-ai/kms-core/commit/63fd2d57c631b83f52d74ef3b02e18a69987e6b5))
* manual workflow ([#686](https://github.com/zama-ai/kms-core/issues/686)) ([4ac7777](https://github.com/zama-ai/kms-core/commit/4ac7777a3a4bc9c03b814cb83af6e481be0c681a))
* manual workflow ([#687](https://github.com/zama-ai/kms-core/issues/687)) ([2f1b8cb](https://github.com/zama-ai/kms-core/commit/2f1b8cb9f75514af7cd34629ed5c356969267e81))
* Needed ([2205057](https://github.com/zama-ai/kms-core/commit/2205057ad4edf73b20ecbae064f4f13e70e28128))
* redacted cyphertext ([#632](https://github.com/zama-ai/kms-core/issues/632)) ([0ec58e0](https://github.com/zama-ai/kms-core/commit/0ec58e01d7b4f7aef2ca418d317df50f32eeb157))
* refactor ([#502](https://github.com/zama-ai/kms-core/issues/502)) ([a69fee2](https://github.com/zama-ai/kms-core/commit/a69fee22e2b40bc35b00301c523bafb2668a9bbb))
* remove enclave docker ([#675](https://github.com/zama-ai/kms-core/issues/675)) ([898f32d](https://github.com/zama-ai/kms-core/commit/898f32d3fede257bb87cd8d96b65d59d2ce8fc57))
* removed superflous protocol directory ([#426](https://github.com/zama-ai/kms-core/issues/426)) ([73a8f31](https://github.com/zama-ai/kms-core/commit/73a8f31857a6c89729207dad45591ace7b757750))
* rename Bool to Ebool ([#709](https://github.com/zama-ai/kms-core/issues/709)) ([9b41bd7](https://github.com/zama-ai/kms-core/commit/9b41bd7d3dc4771f18aff8b59bdc98bda6d661ba))
* run clippy on all features in CI ([#388](https://github.com/zama-ai/kms-core/issues/388)) ([78b97d0](https://github.com/zama-ai/kms-core/commit/78b97d0180c02b9e08518fcbf58aea0925fc671b))
* small fix for overwrite issue in key gen utility ([#707](https://github.com/zama-ai/kms-core/issues/707)) ([0146d77](https://github.com/zama-ai/kms-core/commit/0146d77c8954f69c5ca8166ea88c4d5d6fb61177))
* **storage:** fix merge of storage changes ([#456](https://github.com/zama-ai/kms-core/issues/456)) ([7f1d9f5](https://github.com/zama-ai/kms-core/commit/7f1d9f5141603b6749a5854c06c53c7d7172701e))
* try another approach ([#758](https://github.com/zama-ai/kms-core/issues/758)) ([10acbf7](https://github.com/zama-ai/kms-core/commit/10acbf714a1b1d4008d34f851ac94c4d5e53bb7f))
* try another approach ([#759](https://github.com/zama-ai/kms-core/issues/759)) ([2dd045f](https://github.com/zama-ai/kms-core/commit/2dd045fe39118a569520daee3ebcc3d9544ee61d))
* try another approach ([#760](https://github.com/zama-ai/kms-core/issues/760)) ([6459959](https://github.com/zama-ai/kms-core/commit/64599596bfba0e0011e2f2c9a63dc4a900514353))
* trying some fixing ([#753](https://github.com/zama-ai/kms-core/issues/753)) ([0e36a9c](https://github.com/zama-ai/kms-core/commit/0e36a9ccca246aa14d38038cd2a7569ece2f3b92))
* tx id length and redacted cyphertext in logs ([#630](https://github.com/zama-ai/kms-core/issues/630)) ([0a561c3](https://github.com/zama-ai/kms-core/commit/0a561c36c6ff80dfdb78fafad757903fd14f041a))
* update RequestId and SessionId to spec ([#474](https://github.com/zama-ai/kms-core/issues/474)) ([963aacb](https://github.com/zama-ai/kms-core/commit/963aacb5824a79177ca11f24502467ed56cbf1aa))
* use ok_or_else everywhere, to force lazy eval and avoid logging false info ([#642](https://github.com/zama-ai/kms-core/issues/642)) ([70f4014](https://github.com/zama-ai/kms-core/commit/70f4014b3e11d464e6e6ac1150b8f2779403d3a9))
* wasm build by removing mio from dependency ([#112](https://github.com/zama-ai/kms-core/issues/112)) ([fdcad25](https://github.com/zama-ai/kms-core/commit/fdcad25a4ff79dd5ee32bd5536a609eca879f190))
* **wasm:** fix wasm warnings; put grpc-client under a feature ([#490](https://github.com/zama-ai/kms-core/issues/490)) ([c1d3a7b](https://github.com/zama-ai/kms-core/commit/c1d3a7b1dd63fe23b63769b387e1d9d1aa7b5e12))
* workflow ([#711](https://github.com/zama-ai/kms-core/issues/711)) ([132065d](https://github.com/zama-ai/kms-core/commit/132065d1aa043f5f78786ac349e6e1269a1b47e8))
* workflow enclave image ([#379](https://github.com/zama-ai/kms-core/issues/379)) ([3154e5c](https://github.com/zama-ai/kms-core/commit/3154e5c4aeed0a767053da047ef9980874e1ee06))
* workflow on merge main gh pages permissions ([#378](https://github.com/zama-ai/kms-core/issues/378)) ([96525bc](https://github.com/zama-ai/kms-core/commit/96525bc67b1d01e5afab8adae181ba76bef761a6))
* wrong context ([#465](https://github.com/zama-ai/kms-core/issues/465)) ([80855cc](https://github.com/zama-ai/kms-core/commit/80855ccf346b00fbe1fe7c63c02cc103f24d427e))
* Wrong pipeline Main ([7ab097c](https://github.com/zama-ai/kms-core/commit/7ab097cd1d4abfe002d38360dfd6febb77b28b36))
* Wrong pipeline Main ([a5055cc](https://github.com/zama-ai/kms-core/commit/a5055cc368c33cc4b88eec47e1a5234ccac15f8c))
* zeroize CRS toxic waste and update zk-poc to newest commit ([#373](https://github.com/zama-ai/kms-core/issues/373)) ([1ed4632](https://github.com/zama-ai/kms-core/commit/1ed46325667e9ad30ec729c7ce290caed6a20bd8))


### Features

* add address ([#376](https://github.com/zama-ai/kms-core/issues/376)) ([fe77b37](https://github.com/zama-ai/kms-core/commit/fe77b37c91c156905694cfd3eee0950f4b02289c))
* add cosmwasm support and cosmos ([#367](https://github.com/zama-ai/kms-core/issues/367)) ([c2765e1](https://github.com/zama-ai/kms-core/commit/c2765e19a9042997928a74dc7d3d4a1c766606cd))
* Add new ABI and storage files for gateway contracts ([#737](https://github.com/zama-ai/kms-core/issues/737)) ([4fc09bc](https://github.com/zama-ai/kms-core/commit/4fc09bc51b726a58b18bc250a52e8188cb53186c))
* add pipeline for connector ([#496](https://github.com/zama-ai/kms-core/issues/496)) ([7360074](https://github.com/zama-ai/kms-core/commit/73600741d28a3b6aeeb837ffc08233e04cc8775e))
* added configuration contract ([#386](https://github.com/zama-ai/kms-core/issues/386)) ([567077a](https://github.com/zama-ai/kms-core/commit/567077ad25545cb805cbdaa09e6cdd0e10a0b6ac))
* added debug proof type ([#526](https://github.com/zama-ai/kms-core/issues/526)) ([889109e](https://github.com/zama-ai/kms-core/commit/889109e03777b15889e9eb02524aa05207273dc4))
* added tests for parallel decryption queries (centralized) ([#647](https://github.com/zama-ai/kms-core/issues/647)) ([243094a](https://github.com/zama-ai/kms-core/commit/243094a8896da36075a3bec07107dba358079ef7))
* Adding cargo workspace file ([8f039d9](https://github.com/zama-ai/kms-core/commit/8f039d90263b1377708e6054f99594f72f19f5cc))
* Adds an unencrypted S3 storage backend ([#560](https://github.com/zama-ai/kms-core/issues/560)) ([#598](https://github.com/zama-ai/kms-core/issues/598)) ([033dd90](https://github.com/zama-ai/kms-core/commit/033dd906c135bd7f596211192f40471db0e67bd5))
* Async centralized CRS handling ([#432](https://github.com/zama-ai/kms-core/issues/432)) ([12b0e04](https://github.com/zama-ai/kms-core/commit/12b0e0446eca0830423fb71e90a805445829350b))
* benchmarking BGV using gRPC.  ([#471](https://github.com/zama-ai/kms-core/issues/471)) ([3b484f5](https://github.com/zama-ai/kms-core/commit/3b484f5f18c14a05971339dd2ed9f37b208b5c73))
* **bgv:** Offline phase for BGV structures ([2f9b13d](https://github.com/zama-ai/kms-core/commit/2f9b13df8c3c38355ba1dc49743cdf1e73eda4ff))
* **blockchain:** refactoring types ([#573](https://github.com/zama-ai/kms-core/issues/573)) ([8d737e4](https://github.com/zama-ai/kms-core/commit/8d737e434feb1a4b218739651064ca761e712681))
* **blockchain:** Restrict configuration to admin contract ([#564](https://github.com/zama-ai/kms-core/issues/564)) ([bda385a](https://github.com/zama-ai/kms-core/commit/bda385a7c0e2be1aa49b9509eb54d26b5839403e))
* bls12-446 for CRS ceremony ([#359](https://github.com/zama-ai/kms-core/issues/359)) ([0f6f722](https://github.com/zama-ai/kms-core/commit/0f6f722f8e5a7c20151a41f69345256111769313))
* Changing deployment ([#383](https://github.com/zama-ai/kms-core/issues/383)) ([bfca94a](https://github.com/zama-ai/kms-core/commit/bfca94a04634c29c6c4788391dc070b3ca81d588))
* **CLI:** Making mobygo the NIST CLI for TFHE + stairwayctl for BGV ([#561](https://github.com/zama-ai/kms-core/issues/561)) ([105f124](https://github.com/zama-ai/kms-core/commit/105f124c49ad65f3fd2dbb641efc2cbb6025e446))
* connector integration tests ([#505](https://github.com/zama-ai/kms-core/issues/505)) ([5c015d2](https://github.com/zama-ai/kms-core/commit/5c015d2d6b2d106ec078d0d0bfa98a2555d8b231))
* **connector:** add param choice in config contract ([#622](https://github.com/zama-ai/kms-core/issues/622)) ([afb4692](https://github.com/zama-ai/kms-core/commit/afb46926c6f0717f04cd36f20f67f7b3ec694d5e))
* **connector:** add shares_needed in config contract ([#608](https://github.com/zama-ai/kms-core/issues/608)) ([b3b79ff](https://github.com/zama-ai/kms-core/commit/b3b79ff6b61985485487b7d3e80fc44c5c2fefc2)), closes [#593](https://github.com/zama-ai/kms-core/issues/593)
* **connector:** dec and reenc ([#512](https://github.com/zama-ai/kms-core/issues/512)) ([8a18506](https://github.com/zama-ai/kms-core/commit/8a1850657a53cee1cd485a4f626b66f67e0cd8ca)), closes [#488](https://github.com/zama-ai/kms-core/issues/488)
* **connector:** preproc and keygen ([#495](https://github.com/zama-ai/kms-core/issues/495)) ([1962a09](https://github.com/zama-ai/kms-core/commit/1962a09390468e848e4f91a087fdbf98d3bf07ff))
* **connector:** teach connector to talk to coordinator for crs gen ([#486](https://github.com/zama-ai/kms-core/issues/486)) ([cfeb072](https://github.com/zama-ai/kms-core/commit/cfeb0724f512ac2748cd5294487cefdbc78b8f7e))
* **coordinator:** configure the parameter path ([#572](https://github.com/zama-ai/kms-core/issues/572)) ([4db82e1](https://github.com/zama-ai/kms-core/commit/4db82e1cb70db195d77a7fa4edff4c7a2ff79459))
* **coordinator:** implement address configuration ([#588](https://github.com/zama-ai/kms-core/issues/588)) ([c8d7f7d](https://github.com/zama-ai/kms-core/commit/c8d7f7d82149223544f04be9cc3f6ea054fbf6f3)), closes [#583](https://github.com/zama-ai/kms-core/issues/583)
* **coordinator:** implement timeout configuration ([#534](https://github.com/zama-ai/kms-core/issues/534)) ([ff4e9b5](https://github.com/zama-ai/kms-core/commit/ff4e9b57a7940575f75c11c1862f5282d8ba7bdf))
* **coordinator:** initialize coordinator using a cli ([#595](https://github.com/zama-ai/kms-core/issues/595)) ([98b042e](https://github.com/zama-ai/kms-core/commit/98b042e7765b7df12a2005061e5169cecc476130))
* core to core tls ([#374](https://github.com/zama-ai/kms-core/issues/374)) ([d58124a](https://github.com/zama-ai/kms-core/commit/d58124a42758aeb9904d9ce30d34b74ded7b8707))
* **core:** implement threshold core binary ([#562](https://github.com/zama-ai/kms-core/issues/562)) ([d6bd51a](https://github.com/zama-ai/kms-core/commit/d6bd51a935cef9fcbdd18de1795bbe0304122d7d))
* **core:** introduce testing feature in core/service ([#651](https://github.com/zama-ai/kms-core/issues/651)) ([a72aa1e](https://github.com/zama-ai/kms-core/commit/a72aa1e38cdd0ce3aff2827432f0eda074ce6e2c))
* **core:** modularize threshold kms for better mocking ([#665](https://github.com/zama-ai/kms-core/issues/665)) ([ad0d5f5](https://github.com/zama-ai/kms-core/commit/ad0d5f5ce16025f967e740b2f262f560d070ac69))
* **crs:** add distributed crs functionality for coordinator ([#425](https://github.com/zama-ai/kms-core/issues/425)) ([f69beb7](https://github.com/zama-ai/kms-core/commit/f69beb79acda7f169f37082f149de39aae888506))
* **crs:** correctly compute witness dimension ([#469](https://github.com/zama-ai/kms-core/issues/469)) ([69ebb21](https://github.com/zama-ai/kms-core/commit/69ebb2198f43a512a499ec351ee18411c2d6aa34))
* degrading instance type ([372c988](https://github.com/zama-ai/kms-core/commit/372c98810d45f0ff35024423cd686af512c6ea3b))
* Deploy AWS and CI/CD pipelines ([620e2f5](https://github.com/zama-ai/kms-core/commit/620e2f535c0ce56d70f2c5e4790cbb59c54972a4))
* **dkg:** Adding distributed key generation endpoint ([#458](https://github.com/zama-ai/kms-core/issues/458)) ([b9d90d2](https://github.com/zama-ai/kms-core/commit/b9d90d2205532ec7dbda38c3408426e74561e570))
* document docker compose for customers ([#704](https://github.com/zama-ai/kms-core/issues/704)) ([c22a5b7](https://github.com/zama-ai/kms-core/commit/c22a5b7bac6e1df22058882b233a3117ae68f7f5))
* flag to store plain fhe private key at keygen ([#654](https://github.com/zama-ai/kms-core/issues/654)) ([c744ada](https://github.com/zama-ai/kms-core/commit/c744ada8c3ff5720b321fb33990d9d36a9ddd26f))
* **gateway:** added coprocessor ciphertext retrieval support ([#701](https://github.com/zama-ai/kms-core/issues/701)) ([820cd96](https://github.com/zama-ai/kms-core/commit/820cd9618541dc1e9f46e10d7d5948d23aadaeb1))
* **gateway:** ci pipeline ([#645](https://github.com/zama-ai/kms-core/issues/645)) ([61ae159](https://github.com/zama-ai/kms-core/commit/61ae159439f63bb3a371dcab8b431b861eb32559))
* **gateway:** recover public key from signature ([#744](https://github.com/zama-ai/kms-core/issues/744)) ([7033bb3](https://github.com/zama-ai/kms-core/commit/7033bb3080c8a99464316770d56269fe385fe904))
* **gateway:** reencryption ([#698](https://github.com/zama-ai/kms-core/issues/698)) ([816a6ab](https://github.com/zama-ai/kms-core/commit/816a6ab70e223619f2dd05aaa6da58bf4220a44d))
* **gateway:** Refactor reenc api service ([#774](https://github.com/zama-ai/kms-core/issues/774)) ([3057a02](https://github.com/zama-ai/kms-core/commit/3057a029502a804d6786d7096baec525332c2de3))
* **gateway:** return plaintext for threshold decryption ([#699](https://github.com/zama-ai/kms-core/issues/699)) ([5d00699](https://github.com/zama-ai/kms-core/commit/5d0069972f5912324ae3d7fdc36f0d3b82140030))
* **gateway:** simplify reenc POST API ([#736](https://github.com/zama-ai/kms-core/issues/736)) ([8c4b60f](https://github.com/zama-ai/kms-core/commit/8c4b60f68c2bed85e748bba4064b2b4f8d10a883))
* generate TLS certs ([#362](https://github.com/zama-ai/kms-core/issues/362)) ([2a1e99b](https://github.com/zama-ai/kms-core/commit/2a1e99b8e4a24fde2e09d4866898eb58b243e440))
* Make Release CI pipeline ([#742](https://github.com/zama-ai/kms-core/issues/742)) ([fdda4bb](https://github.com/zama-ai/kms-core/commit/fdda4bb9300ec6ce03c3bf727a92e88a3e27da12))
* merge distributed-decryption repo into this ([48de569](https://github.com/zama-ai/kms-core/commit/48de569e581e8213434a4baf06d21dd2ac2c8133))
* **network:**  Adding possibility to change timeout during protocol execution ([#693](https://github.com/zama-ai/kms-core/issues/693)) ([f7d5ba8](https://github.com/zama-ai/kms-core/commit/f7d5ba81c0515362baec0847c2688509d0e9afc5))
* New Configuration setup for ddec and choreographer ([#337](https://github.com/zama-ai/kms-core/issues/337)) ([3f9c251](https://github.com/zama-ai/kms-core/commit/3f9c251d9ae7ff3284d1de152eed330fe29c2b2a))
* new version ([#728](https://github.com/zama-ai/kms-core/issues/728)) ([702d6b6](https://github.com/zama-ai/kms-core/commit/702d6b62cc493051bc701b00ecf42899e6dd6a9b))
* prepare for mono-repo ([eb98e92](https://github.com/zama-ai/kms-core/commit/eb98e9234d726822036de15f7e17d5af77cb37c8))
* prepare for monorepo ([887e582](https://github.com/zama-ai/kms-core/commit/887e582e420f112f0e322b29781a843188395d08))
* **prss:** Write PRSS setup to disk on threshold server init, and load on restart ([#660](https://github.com/zama-ai/kms-core/issues/660)) ([a57d4c5](https://github.com/zama-ai/kms-core/commit/a57d4c572819c3ddca5db11344534ffa8c4ec4e0))
* **reenc:** update reencryption protocol to spec ([#530](https://github.com/zama-ai/kms-core/issues/530)) ([b75d9b2](https://github.com/zama-ai/kms-core/commit/b75d9b24500e0c7d4ca440bbb977690e9c9c52f5))
* revamped gateway oracle service ([#594](https://github.com/zama-ai/kms-core/issues/594)) ([bfd4e18](https://github.com/zama-ai/kms-core/commit/bfd4e1800b95936adac41da43ba685d5a28a1897)), closes [#561](https://github.com/zama-ai/kms-core/issues/561) [#608](https://github.com/zama-ai/kms-core/issues/608) [#593](https://github.com/zama-ai/kms-core/issues/593) [#623](https://github.com/zama-ai/kms-core/issues/623) [#622](https://github.com/zama-ai/kms-core/issues/622) [#607](https://github.com/zama-ai/kms-core/issues/607) [#624](https://github.com/zama-ai/kms-core/issues/624) [#625](https://github.com/zama-ai/kms-core/issues/625) [#592](https://github.com/zama-ai/kms-core/issues/592) [#630](https://github.com/zama-ai/kms-core/issues/630) [#596](https://github.com/zama-ai/kms-core/issues/596)
* rework orchestrator +  tracing ([#532](https://github.com/zama-ai/kms-core/issues/532)) ([d011b83](https://github.com/zama-ai/kms-core/commit/d011b83a43b247049da9494a510418e26799e443))
* simulate full flow with scripts ([#585](https://github.com/zama-ai/kms-core/issues/585)) ([e5fe0b4](https://github.com/zama-ai/kms-core/commit/e5fe0b45b933ba5c420ffcae3cb536f70854073d))
* Starting refactoring tests ([#361](https://github.com/zama-ai/kms-core/issues/361)) ([f9e5f8e](https://github.com/zama-ai/kms-core/commit/f9e5f8eca659d29cb38f2090ee34040a6dedbb5a))
* starting with oracle connector ([#508](https://github.com/zama-ai/kms-core/issues/508)) ([ef67549](https://github.com/zama-ai/kms-core/commit/ef67549b11d7ef6a0901e0bfcba6efe0b849f43e))
* **storage:** configure custom storage paths ([#581](https://github.com/zama-ai/kms-core/issues/581)) ([abb07d2](https://github.com/zama-ai/kms-core/commit/abb07d2ea2b193c793dd401d1dda2a21b50c7e62))
* **storage:** modify DevStorage to handle threshold setting ([#445](https://github.com/zama-ai/kms-core/issues/445)) ([e32947e](https://github.com/zama-ai/kms-core/commit/e32947ee03276f86f63ab98b3be9972999a721c0))
* **tfhe:** upgrade to 0.6.1 ([#415](https://github.com/zama-ai/kms-core/issues/415)) ([30ad113](https://github.com/zama-ai/kms-core/commit/30ad113031ece6424bd7287c14833ac5b75e2cda))
* threshold decryption for BFV ([#592](https://github.com/zama-ai/kms-core/issues/592)) ([214ec4b](https://github.com/zama-ai/kms-core/commit/214ec4bdc16a36408ae83826292af039c262b579))
* **tls:** Per-Party TLS setup ([#555](https://github.com/zama-ai/kms-core/issues/555)) ([9e4accb](https://github.com/zama-ai/kms-core/commit/9e4accb7fd57c39bf4d887cb1c52e5869d5da8c5))
* **tls:** split the core and mobygo endpoints ([#399](https://github.com/zama-ai/kms-core/issues/399)) ([cb5a123](https://github.com/zama-ai/kms-core/commit/cb5a123d7e9b03660eddc325d256561ab91327f3))
* **tls:** TLS between KMS cores ([#596](https://github.com/zama-ai/kms-core/issues/596)) ([908ad71](https://github.com/zama-ai/kms-core/commit/908ad71f91e63403cda7b6e09e52702625b3255e))
* Update variable name in handle_reencryption_event ([#745](https://github.com/zama-ai/kms-core/issues/745)) ([f84e172](https://github.com/zama-ai/kms-core/commit/f84e17212439048d7176fcaeb3e311dbc2c11c46))
* wasm on kms ([#110](https://github.com/zama-ai/kms-core/issues/110)) ([bde1129](https://github.com/zama-ai/kms-core/commit/bde1129c781982319a2037f37eedf23621b6b3d9))
* **wasm:** add de/serialize to encryption keys pairs ([#542](https://github.com/zama-ai/kms-core/issues/542)) ([b5923f3](https://github.com/zama-ai/kms-core/commit/b5923f3199418c506135f0dc87526e76c1d3fe62))
