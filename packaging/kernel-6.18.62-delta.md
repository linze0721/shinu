# Linux 6.1.155 → 6.18.62 完整 =y 差集

比较 109 自编 6.1.155 config 与原始 FC-CI 6.18.62 config 的所有 `CONFIG_*=y`，不限 netfilter。原始 CI 差集共 111 项；最终 config 逐项状态如下。Kconfig 是否存在已对 Linux 6.18.62 源码逐文件核验。

最终 kernel SHA-256: `423c1ddb2f265b460b7b7a6abd37f21d1b03acf5c0c07470247b75455f0675d4`；config SHA-256: `8ab6cdca47da451376755a16bf0b659306126e9d8def6b3a8e5299369647e8c2`。

DUMMY 是实测新增的必要依赖：`leapbench-origin.service` 创建 `enorigin type dummy`，缺失时 Docker dependency 失败。保留 MACVLAN/IPVLAN、CUSE/virtio-fs/FUSE DAX、SUNRPC GSS 及所有仍存在的旧 crypto 项。BRIDGE/VETH/VXLAN/TUN、OVERLAY/FUSE/SQUASHFS/BTRFS/XFS/NFS、cgroup/ns 和模块加载等未出现在差集的旧 =y 项，本来已在新 config 内建。

| 旧 =y 项 | 原始 CI | 最终 | 处置依据 |
|---|---|---|---|
| `CONFIG_ARCH_HAS_KEXEC_PURGATORY` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_ARCH_HAS_PTE_DEVMAP` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_ARCH_HAS_UBSAN_SANITIZE_ALL` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_ARCH_SUPPORTS_CFI_CLANG` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_ARCH_USES_PG_UNCACHED` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_ARCH_WANT_HUGETLB_PAGE_OPTIMIZE_VMEMMAP` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_AS_AVX512` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_AS_HAS_NON_CONST_LEB128` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_AS_SHA1_NI` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_AS_SHA256_NI` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_AS_TPAUSE` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_AUTOFS4_FS` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_BASE_FULL` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_BLK_MQ_PCI` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_BLK_MQ_VIRTIO` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_BLOCK_COMPAT` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_BPFILTER` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_BPFILTER_UMH` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CC_CAN_LINK_STATIC` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CC_HAS_KASAN_SW_TAGS` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_CC_HAS_SANCOV_TRACE_PC` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CC_HAS_SANE_STACKPROTECTOR` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CLOCKSOURCE_VALIDATE_LAST_CYCLE` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CPU_IBPB_ENTRY` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CPU_IBRS_ENTRY` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CPU_SRSO` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CPU_UNRET_ENTRY` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CRASH_CORE` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CRC32_SLICEBY8` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CRYPTO_CRCT10DIF` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CRYPTO_CRCT10DIF_PCLMUL` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CRYPTO_LIB_BLAKE2S_GENERIC` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CRYPTO_MANAGER_DISABLE_TESTS` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CRYPTO_NULL2` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CRYPTO_SHA1_SSSE3` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CRYPTO_SHA256_SSSE3` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CRYPTO_SHA512_SSSE3` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_CUSE` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_DAMON_DBGFS` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_DMA_OPS` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_DUMMY` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_DYNAMIC_MEMORY_LAYOUT` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_FRONTSWAP` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_FUSE_DAX` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_GENERIC_CPU` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_GENERIC_MSI_IRQ_DOMAIN` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_GENERIC_PTDUMP` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_GENERIC_VDSO_TIME_NS` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_HAVE_ARCH_STACKLEAK` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_HAVE_FAST_GUP` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_HAVE_FTRACE_MCOUNT_RECORD` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_HAVE_HARDENED_USERCOPY_ALLOCATOR` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_HAVE_KVM` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_HID` | n/absent | n/absent | 无 USB/HID/硬件显示设备的 Firecracker guest；串口和 VNC 软件输入不依赖此驱动 |
| `CONFIG_HIDRAW` | n/absent | n/absent | 无 USB/HID/硬件显示设备的 Firecracker guest；串口和 VNC 软件输入不依赖此驱动 |
| `CONFIG_HW_CONSOLE` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_INTERVAL_TREE` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_IP6_NF_RAW` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_IPVLAN` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_IPVLAN_L3S` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_IP_NF_RAW` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_IP_VS` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_IP_VS_NFCT` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_IP_VS_RR` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_IRQ_MSI_IOMMU` | n/absent | n/absent | 架构、工具链或隐含依赖探测项；保留 6.18 自动选择，不手工覆盖探测结果 |
| `CONFIG_KALLSYMS_ABSOLUTE_PERCPU` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_KALLSYMS_BASE_RELATIVE` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_LIBCRC32C` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_MACVLAN` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_MEMCG_KMEM` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_NETFILTER_XT_MATCH_COMMENT` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NETFILTER_XT_MATCH_IPVS` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NETFILTER_XT_MATCH_MARK` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NETFILTER_XT_MATCH_MULTIPORT` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NETFILTER_XT_TARGET_CHECKSUM` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NFT_FIB` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NFT_FIB_IPV4` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NFT_FIB_IPV6` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NFT_LIMIT` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NFT_LOG` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NFT_MASQ` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NFT_REJECT` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NFT_REJECT_INET` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NFT_REJECT_IPV4` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NFT_REJECT_IPV6` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NF_CT_PROTO_DCCP` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_NF_TABLES_INET` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_NF_TABLES_IPV6` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_PAGE_TABLE_ISOLATION` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_PCI_MSI_IRQ_DOMAIN` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_PSTORE_DEFLATE_COMPRESS` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_PSTORE_DEFLATE_COMPRESS_DEFAULT` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_PTE_MARKER` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_RANDOM_TRUST_BOOTLOADER` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_RANDOM_TRUST_CPU` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_RETHUNK` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_RETPOLINE` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_SECURITY_SELINUX_DISABLE` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_SECURITY_WRITABLE_HOOKS` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_SRCU` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_SUNRPC_GSS` | n/absent | y | 通过 `RPCSEC_GSS_KRB5=y` 的正式 selector 补齐 hidden GSS 符号及 crypto 依赖 |
| `CONFIG_THERMAL_WRITABLE_TRIPS` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_USERMODE_DRIVER` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_VIRTIO_FS` | n/absent | y | 补齐为内建 / 新版依赖自动选择，保留旧运行能力 |
| `CONFIG_X86_64_SMP` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_X86_CMPXCHG64` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_X86_FEATURE_NAMES` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_XZ_DEC_IA64` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_ZBUD` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_ZPOOL` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
| `CONFIG_ZSWAP_ZPOOL_DEFAULT_ZBUD` | n/absent | n/absent | 6.18 已删除或重命名该 Kconfig 符号；旧名称不能代表功能关闭 |
