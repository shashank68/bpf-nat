; ModuleID = 'nat64_kern.c'
source_filename = "nat64_kern.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%struct.nat64_config = type { %struct.in6_addr, i64, i64, i32, i32 }
%struct.in6_addr = type { %union.anon.3 }
%union.anon.3 = type { [4 x i32] }
%struct.anon.4 = type { [1 x i32]*, %struct.in6_addr*, %struct.v6_addr_state*, [1 x i32]*, [1 x i32]* }
%struct.v6_addr_state = type { i64, i32, i32 }
%struct.anon.5 = type { [1 x i32]*, i32*, %struct.in6_addr*, [1 x i32]*, [1 x i32]* }
%struct.anon.6 = type { [11 x i32]*, [16 x i32]*, [4 x i32]*, [1 x i32]*, [1 x i32]* }
%struct.anon.7 = type { [22 x i32]*, [0 x i32]*, [4 x i32]*, [1 x i32]* }
%struct.v6_trie_key = type { %struct.bpf_lpm_trie_key, %struct.in6_addr }
%struct.bpf_lpm_trie_key = type { i32, [0 x i8] }
%struct.iphdr = type { i8, i8, i16, i16, i16, i8, i8, i16, i32, i32 }
%struct.__sk_buff = type { i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, [5 x i32], i32, i32, i32, i32, i32, i32, i32, i32, [4 x i32], [4 x i32], i32, i32, i32, %union.anon, i64, i32, i32, %union.anon.2, i32 }
%union.anon = type { %struct.bpf_flow_keys* }
%struct.bpf_flow_keys = type { i16, i16, i16, i8, i8, i8, i8, i16, i16, i16, %union.anon.0, i32, i32 }
%union.anon.0 = type { %struct.anon.1 }
%struct.anon.1 = type { [4 x i32], [4 x i32] }
%union.anon.2 = type { %struct.bpf_sock* }
%struct.bpf_sock = type { i32, i32, i32, i32, i32, i32, i32, [4 x i32], i32, i32, i32, [4 x i32], i32, i32 }
%struct.ethhdr = type { [6 x i8], [6 x i8], i16 }
%struct.hdr_cursor = type { i8* }
%struct.collect_vlans = type { [2 x i16] }
%struct.vlan_hdr = type { i16, i16 }
%struct.ipv6hdr = type { i8, [3 x i8], i16, i8, i8, %struct.in6_addr, %struct.in6_addr }
%struct.bpf_redir_neigh = type { i32, %union.anon.8 }
%union.anon.8 = type { [4 x i32] }
%struct.bpf_map = type opaque

@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1, !dbg !0
@config = dso_local global %struct.nat64_config zeroinitializer, align 8, !dbg !31
@v6_state_map = dso_local global %struct.anon.4 zeroinitializer, section ".maps", align 8, !dbg !62
@v4_reversemap = dso_local global %struct.anon.5 zeroinitializer, section ".maps", align 8, !dbg !83
@allowed_v6_src = dso_local global %struct.anon.6 zeroinitializer, section ".maps", align 8, !dbg !93
@reclaimed_addrs = dso_local global %struct.anon.7 zeroinitializer, section ".maps", align 8, !dbg !110
@__const.nat64_handle_v4.____fmt = private unnamed_addr constant [76 x i8] c"nat64: v4: pkt src/dst %pI4/%pI4 has IP options or is fragmented, dropping\0A\00", align 1
@__const.nat64_handle_v4.____fmt.1 = private unnamed_addr constant [42 x i8] c"nat64: v4: no mapping found for dst %pI4\0A\00", align 1
@__const.nat64_handle_v4.____fmt.2 = private unnamed_addr constant [48 x i8] c"nat64: v4: Found mapping for dst %pI4 to %pI6c\0A\00", align 1
@__const.nat64_handle_v6.saddr_key = private unnamed_addr constant %struct.v6_trie_key { %struct.bpf_lpm_trie_key { i32 128, [0 x i8] zeroinitializer }, %struct.in6_addr zeroinitializer }, align 4
@__const.nat64_handle_v6.dst_hdr = private unnamed_addr constant %struct.iphdr { i8 69, i8 0, i16 0, i16 0, i16 64, i8 0, i8 0, i16 0, i32 0, i32 0 }, align 4
@__const.nat64_handle_v6.____fmt = private unnamed_addr constant [60 x i8] c"nat64: v6: dst subnet %pI6c not in configured prefix %pI6c\0A\00", align 1
@__const.nat64_handle_v6.____fmt.3 = private unnamed_addr constant [55 x i8] c"nat64: v6: dropping packet with IP options from %pI6c\0A\00", align 1
@__const.nat64_handle_v6.____fmt.4 = private unnamed_addr constant [52 x i8] c"nat64: v6: dropping invalid v4 dst %pI4 from %pI6c\0A\00", align 1
@__const.nat64_handle_v6.____fmt.5 = private unnamed_addr constant [43 x i8] c"nat64: v6: saddr %pI6c not in allowed src\0A\00", align 1
@__const.nat64_handle_v6.____fmt.6 = private unnamed_addr constant [51 x i8] c"nat64: v6: failed to allocate state for src %pI6c\0A\00", align 1
@__const.nat64_handle_v6.____fmt.7 = private unnamed_addr constant [51 x i8] c"nat64: v6: created new state for v6 %pI6c -> %pI4\0A\00", align 1
@__const.nat64_handle_v6.____fmt.8 = private unnamed_addr constant [51 x i8] c"nat64: v6: updated old state for v6 %pI6c -> %pI4\0A\00", align 1
@llvm.compiler.used = appending global [7 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (%struct.anon.6* @allowed_v6_src to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @nat64_egress to i8*), i8* bitcast (i32 (%struct.__sk_buff*)* @nat64_ingress to i8*), i8* bitcast (%struct.anon.7* @reclaimed_addrs to i8*), i8* bitcast (%struct.anon.5* @v4_reversemap to i8*), i8* bitcast (%struct.anon.4* @v6_state_map to i8*)], section "llvm.metadata"

; Function Attrs: nounwind
define dso_local i32 @nat64_egress(%struct.__sk_buff* %0) #0 section "classifier" !dbg !301 {
  call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !305, metadata !DIExpression()), !dbg !306
  %2 = tail call fastcc i32 @nat64_handler(%struct.__sk_buff* %0, i1 zeroext true), !dbg !307
  ret i32 %2, !dbg !308
}

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: nounwind
define internal fastcc i32 @nat64_handler(%struct.__sk_buff* %0, i1 zeroext %1) unnamed_addr #0 !dbg !309 {
  %3 = alloca %struct.v6_trie_key, align 4
  %4 = alloca %struct.in6_addr, align 4
  %5 = alloca i32, align 4
  %6 = alloca i32, align 4
  %7 = alloca %struct.iphdr, align 4
  %8 = alloca [60 x i8], align 1
  %9 = alloca [55 x i8], align 1
  %10 = alloca [52 x i8], align 1
  %11 = alloca [43 x i8], align 1
  %12 = alloca [51 x i8], align 1
  %13 = alloca [51 x i8], align 1
  %14 = alloca [51 x i8], align 1
  %15 = alloca i32, align 4
  %16 = alloca [3 x i32], align 4
  %17 = alloca [4 x i32], align 4
  %18 = alloca [76 x i8], align 1
  %19 = alloca [42 x i8], align 1
  %20 = alloca [48 x i8], align 1
  call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !314, metadata !DIExpression()), !dbg !335
  call void @llvm.dbg.value(metadata i1 %1, metadata !315, metadata !DIExpression(DW_OP_LLVM_convert, 1, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !335
  %21 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 16, !dbg !336
  %22 = load i32, i32* %21, align 8, !dbg !336, !tbaa !337
  %23 = zext i32 %22 to i64, !dbg !343
  %24 = inttoptr i64 %23 to i8*, !dbg !344
  call void @llvm.dbg.value(metadata i8* %24, metadata !316, metadata !DIExpression()), !dbg !335
  %25 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 15, !dbg !345
  %26 = load i32, i32* %25, align 4, !dbg !345, !tbaa !346
  %27 = zext i32 %26 to i64, !dbg !347
  %28 = inttoptr i64 %27 to i8*, !dbg !348
  call void @llvm.dbg.value(metadata i8* %28, metadata !317, metadata !DIExpression()), !dbg !335
  call void @llvm.dbg.value(metadata i8* %28, metadata !318, metadata !DIExpression()), !dbg !335
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !323, metadata !DIExpression(DW_OP_deref)), !dbg !335
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !349, metadata !DIExpression()) #7, !dbg !358
  call void @llvm.dbg.value(metadata i8* %24, metadata !356, metadata !DIExpression()) #7, !dbg !358
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !357, metadata !DIExpression()) #7, !dbg !358
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !360, metadata !DIExpression()) #7, !dbg !385
  call void @llvm.dbg.value(metadata i8* %24, metadata !372, metadata !DIExpression()) #7, !dbg !385
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !373, metadata !DIExpression()) #7, !dbg !385
  call void @llvm.dbg.value(metadata %struct.collect_vlans* null, metadata !374, metadata !DIExpression()) #7, !dbg !385
  call void @llvm.dbg.value(metadata i8* %28, metadata !375, metadata !DIExpression()) #7, !dbg !385
  call void @llvm.dbg.value(metadata i32 14, metadata !376, metadata !DIExpression()) #7, !dbg !385
  %29 = getelementptr i8, i8* %28, i64 14, !dbg !387
  %30 = icmp ugt i8* %29, %24, !dbg !389
  br i1 %30, label %422, label %31, !dbg !390

31:                                               ; preds = %2
  call void @llvm.dbg.value(metadata i8* %28, metadata !375, metadata !DIExpression()) #7, !dbg !385
  call void @llvm.dbg.value(metadata i8* %29, metadata !318, metadata !DIExpression()), !dbg !335
  call void @llvm.dbg.value(metadata i8* %29, metadata !377, metadata !DIExpression()) #7, !dbg !385
  %32 = getelementptr inbounds i8, i8* %28, i64 12, !dbg !391
  %33 = bitcast i8* %32 to i16*, !dbg !391
  call void @llvm.dbg.value(metadata i16 undef, metadata !383, metadata !DIExpression()) #7, !dbg !385
  call void @llvm.dbg.value(metadata i32 0, metadata !384, metadata !DIExpression()) #7, !dbg !385
  %34 = inttoptr i64 %23 to %struct.vlan_hdr*
  %35 = load i16, i16* %33, align 1, !dbg !385, !tbaa !392
  call void @llvm.dbg.value(metadata i16 %35, metadata !383, metadata !DIExpression()) #7, !dbg !385
  call void @llvm.dbg.value(metadata i16 %35, metadata !394, metadata !DIExpression()) #7, !dbg !399
  %36 = icmp eq i16 %35, 129, !dbg !405
  %37 = icmp ne i16 %35, -22392, !dbg !406
  %38 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %36) #7
  %39 = xor i1 %38, true, !dbg !406
  %40 = select i1 %39, i1 %37, i1 false, !dbg !406
  br i1 %40, label %62, label %41, !dbg !407

41:                                               ; preds = %31
  %42 = getelementptr i8, i8* %28, i64 18, !dbg !408
  %43 = bitcast i8* %42 to %struct.vlan_hdr*, !dbg !408
  %44 = icmp ugt %struct.vlan_hdr* %43, %34, !dbg !410
  br i1 %44, label %62, label %45, !dbg !411

45:                                               ; preds = %41
  call void @llvm.dbg.value(metadata i16 undef, metadata !383, metadata !DIExpression()) #7, !dbg !385
  %46 = getelementptr i8, i8* %28, i64 16, !dbg !412
  %47 = bitcast i8* %46 to i16*, !dbg !412
  call void @llvm.dbg.value(metadata %struct.vlan_hdr* %43, metadata !377, metadata !DIExpression()) #7, !dbg !385
  call void @llvm.dbg.value(metadata i32 1, metadata !384, metadata !DIExpression()) #7, !dbg !385
  %48 = load i16, i16* %47, align 1, !dbg !385, !tbaa !392
  call void @llvm.dbg.value(metadata i16 %48, metadata !383, metadata !DIExpression()) #7, !dbg !385
  call void @llvm.dbg.value(metadata i16 %48, metadata !394, metadata !DIExpression()) #7, !dbg !399
  %49 = icmp eq i16 %48, 129, !dbg !405
  %50 = icmp ne i16 %48, -22392, !dbg !406
  %51 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %49) #7
  %52 = xor i1 %51, true, !dbg !406
  %53 = select i1 %52, i1 %50, i1 false, !dbg !406
  br i1 %53, label %62, label %54, !dbg !407

54:                                               ; preds = %45
  %55 = getelementptr i8, i8* %28, i64 22, !dbg !408
  %56 = bitcast i8* %55 to %struct.vlan_hdr*, !dbg !408
  %57 = icmp ugt %struct.vlan_hdr* %56, %34, !dbg !410
  br i1 %57, label %62, label %58, !dbg !411

58:                                               ; preds = %54
  call void @llvm.dbg.value(metadata i16 undef, metadata !383, metadata !DIExpression()) #7, !dbg !385
  %59 = getelementptr i8, i8* %28, i64 20, !dbg !412
  %60 = bitcast i8* %59 to i16*, !dbg !412
  call void @llvm.dbg.value(metadata %struct.vlan_hdr* %56, metadata !377, metadata !DIExpression()) #7, !dbg !385
  call void @llvm.dbg.value(metadata i32 2, metadata !384, metadata !DIExpression()) #7, !dbg !385
  %61 = load i16, i16* %60, align 1, !dbg !385, !tbaa !392
  call void @llvm.dbg.value(metadata i16 %61, metadata !383, metadata !DIExpression()) #7, !dbg !385
  br label %62

62:                                               ; preds = %31, %41, %45, %54, %58
  %63 = phi i8* [ %29, %41 ], [ %29, %31 ], [ %42, %45 ], [ %42, %54 ], [ %55, %58 ], !dbg !385
  %64 = phi i16 [ %35, %41 ], [ %35, %31 ], [ %48, %45 ], [ %48, %54 ], [ %61, %58 ], !dbg !385
  call void @llvm.dbg.value(metadata i8* %63, metadata !318, metadata !DIExpression()), !dbg !335
  call void @llvm.dbg.value(metadata i16 %64, metadata !334, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !335
  %65 = icmp ne i16 %64, 8, !dbg !413
  %66 = xor i1 %1, true, !dbg !415
  %67 = select i1 %65, i1 true, i1 %66, !dbg !415
  br i1 %67, label %179, label %68, !dbg !415

68:                                               ; preds = %62
  call void @llvm.dbg.declare(metadata [3 x i32]* %16, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 64, 96)) #7, !dbg !485
  call void @llvm.dbg.declare(metadata [4 x i32]* %17, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 192, 128)) #7, !dbg !485
  call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !421, metadata !DIExpression()) #7, !dbg !487
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !422, metadata !DIExpression()) #7, !dbg !487
  call void @llvm.dbg.value(metadata i8* %24, metadata !423, metadata !DIExpression()) #7, !dbg !487
  call void @llvm.dbg.value(metadata i32 %26, metadata !424, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !487
  call void @llvm.dbg.value(metadata i32 0, metadata !445, metadata !DIExpression()) #7, !dbg !487
  %69 = bitcast i32* %15 to i8*, !dbg !488
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %69) #7, !dbg !488
  %70 = bitcast [3 x i32]* %16 to i8*, !dbg !489
  call void @llvm.lifetime.start.p0i8(i64 12, i8* nonnull %70), !dbg !489
  %71 = bitcast [4 x i32]* %17 to i8*, !dbg !489
  call void @llvm.lifetime.start.p0i8(i64 16, i8* nonnull %71), !dbg !489
  call void @llvm.dbg.value(metadata i8 96, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 8)) #7, !dbg !487
  call void @llvm.dbg.value(metadata i8 0, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 8, 8)) #7, !dbg !487
  call void @llvm.dbg.value(metadata i16 0, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !487
  call void @llvm.dbg.value(metadata i16 0, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 16)) #7, !dbg !487
  call void @llvm.dbg.value(metadata i8 0, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 48, 8)) #7, !dbg !487
  call void @llvm.dbg.value(metadata i8 0, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 56, 8)) #7, !dbg !487
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(12) %70, i8* noundef nonnull align 8 dereferenceable(12) bitcast (%struct.nat64_config* @config to i8*), i64 12, i1 false) #7, !dbg !490, !tbaa.struct !491
  call void @llvm.dbg.value(metadata i32 undef, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 160, 32)) #7, !dbg !487
  %72 = ptrtoint i8* %63 to i64, !dbg !493
  %73 = trunc i64 %72 to i32, !dbg !494
  %74 = sub i32 %73, %26, !dbg !494
  %75 = and i32 %74, 8191, !dbg !494
  call void @llvm.dbg.value(metadata i32 %75, metadata !427, metadata !DIExpression()) #7, !dbg !487
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !495, metadata !DIExpression()) #7, !dbg !505
  call void @llvm.dbg.value(metadata i8* %24, metadata !501, metadata !DIExpression()) #7, !dbg !505
  call void @llvm.dbg.value(metadata %struct.iphdr** undef, metadata !502, metadata !DIExpression()) #7, !dbg !505
  call void @llvm.dbg.value(metadata i8* %63, metadata !503, metadata !DIExpression()) #7, !dbg !505
  %76 = getelementptr inbounds i8, i8* %63, i64 20, !dbg !507
  %77 = icmp ugt i8* %76, %24, !dbg !509
  br i1 %77, label %177, label %78, !dbg !510

78:                                               ; preds = %68
  %79 = load i8, i8* %63, align 4, !dbg !511
  %80 = and i8 %79, -16, !dbg !513
  %81 = icmp eq i8 %80, 64, !dbg !513
  br i1 %81, label %82, label %177, !dbg !514

82:                                               ; preds = %78
  %83 = shl i8 %79, 2, !dbg !515
  %84 = and i8 %83, 60, !dbg !515
  call void @llvm.dbg.value(metadata i8 %84, metadata !504, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !505
  %85 = icmp ult i8 %84, 20, !dbg !516
  br i1 %85, label %177, label %86, !dbg !518

86:                                               ; preds = %82
  %87 = zext i8 %84 to i64
  call void @llvm.dbg.value(metadata i64 %87, metadata !504, metadata !DIExpression()) #7, !dbg !505
  %88 = getelementptr i8, i8* %63, i64 %87, !dbg !519
  %89 = icmp ugt i8* %88, %24, !dbg !521
  br i1 %89, label %177, label %90, !dbg !522

90:                                               ; preds = %86
  call void @llvm.dbg.value(metadata i8* %88, metadata !318, metadata !DIExpression()), !dbg !335
  call void @llvm.dbg.value(metadata i8 undef, metadata !425, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !487
  call void @llvm.dbg.value(metadata i8* %63, metadata !446, metadata !DIExpression()) #7, !dbg !487
  %91 = getelementptr inbounds i8, i8* %63, i64 16, !dbg !523
  %92 = bitcast i8* %91 to i32*, !dbg !523
  %93 = load i32, i32* %92, align 4, !dbg !523, !tbaa !524
  %94 = tail call i32 @llvm.bswap.i32(i32 %93) #7, !dbg !523
  call void @llvm.dbg.value(metadata i32 %94, metadata !464, metadata !DIExpression()) #7, !dbg !487
  store i32 %94, i32* %15, align 4, !dbg !526, !tbaa !527
  %95 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 4), align 4, !dbg !528, !tbaa !530
  %96 = and i32 %95, %94, !dbg !533
  %97 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 3), align 8, !dbg !534, !tbaa !535
  %98 = icmp eq i32 %96, %97, !dbg !536
  br i1 %98, label %99, label %177, !dbg !537

99:                                               ; preds = %90
  call void @llvm.dbg.value(metadata i32 2, metadata !445, metadata !DIExpression()) #7, !dbg !487
  call void @llvm.dbg.value(metadata i8* %63, metadata !446, metadata !DIExpression()) #7, !dbg !487
  %100 = load i8, i8* %63, align 4, !dbg !538
  call void @llvm.dbg.value(metadata i8 %100, metadata !426, metadata !DIExpression(DW_OP_constu, 2, DW_OP_shl, DW_OP_constu, 60, DW_OP_and, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !487
  %101 = and i8 %100, 15, !dbg !539
  %102 = icmp eq i8 %101, 5, !dbg !539
  br i1 %102, label %103, label %109, !dbg !540

103:                                              ; preds = %99
  %104 = getelementptr inbounds i8, i8* %63, i64 6, !dbg !541
  %105 = bitcast i8* %104 to i16*, !dbg !541
  %106 = load i16, i16* %105, align 2, !dbg !541, !tbaa !542
  %107 = and i16 %106, -65, !dbg !543
  %108 = icmp eq i16 %107, 0, !dbg !543
  br i1 %108, label %113, label %109, !dbg !544

109:                                              ; preds = %103, %99
  %110 = getelementptr inbounds [76 x i8], [76 x i8]* %18, i64 0, i64 0, !dbg !545
  call void @llvm.lifetime.start.p0i8(i64 76, i8* nonnull %110) #7, !dbg !545
  call void @llvm.dbg.declare(metadata [76 x i8]* %18, metadata !465, metadata !DIExpression()) #7, !dbg !545
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(76) %110, i8* noundef nonnull align 1 dereferenceable(76) getelementptr inbounds ([76 x i8], [76 x i8]* @__const.nat64_handle_v4.____fmt, i64 0, i64 0), i64 76, i1 false) #7, !dbg !545
  call void @llvm.dbg.value(metadata i8* %63, metadata !446, metadata !DIExpression()) #7, !dbg !487
  %111 = getelementptr inbounds i8, i8* %63, i64 12, !dbg !545
  %112 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* nonnull %110, i32 76, i8* nonnull %91, i8* nonnull %111) #7, !dbg !545
  call void @llvm.lifetime.end.p0i8(i64 76, i8* nonnull %110) #7, !dbg !546
  br label %177, !dbg !547

113:                                              ; preds = %103
  call void @llvm.dbg.value(metadata i32* %15, metadata !464, metadata !DIExpression(DW_OP_deref)) #7, !dbg !487
  %114 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.anon.5* @v4_reversemap to i8*), i8* nonnull %69) #7, !dbg !548
  call void @llvm.dbg.value(metadata i8* %114, metadata !428, metadata !DIExpression()) #7, !dbg !487
  %115 = icmp eq i8* %114, null, !dbg !549
  br i1 %115, label %116, label %119, !dbg !550

116:                                              ; preds = %113
  %117 = getelementptr inbounds [42 x i8], [42 x i8]* %19, i64 0, i64 0, !dbg !551
  call void @llvm.lifetime.start.p0i8(i64 42, i8* nonnull %117) #7, !dbg !551
  call void @llvm.dbg.declare(metadata [42 x i8]* %19, metadata !472, metadata !DIExpression()) #7, !dbg !551
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(42) %117, i8* noundef nonnull align 1 dereferenceable(42) getelementptr inbounds ([42 x i8], [42 x i8]* @__const.nat64_handle_v4.____fmt.1, i64 0, i64 0), i64 42, i1 false) #7, !dbg !551
  call void @llvm.dbg.value(metadata i8* %63, metadata !446, metadata !DIExpression()) #7, !dbg !487
  %118 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* nonnull %117, i32 42, i8* nonnull %91) #7, !dbg !551
  call void @llvm.lifetime.end.p0i8(i64 42, i8* nonnull %117) #7, !dbg !552
  br label %177, !dbg !553

119:                                              ; preds = %113
  call void @llvm.dbg.value(metadata i8* %114, metadata !428, metadata !DIExpression()) #7, !dbg !487
  %120 = getelementptr inbounds [48 x i8], [48 x i8]* %20, i64 0, i64 0, !dbg !554
  call void @llvm.lifetime.start.p0i8(i64 48, i8* nonnull %120) #7, !dbg !554
  call void @llvm.dbg.declare(metadata [48 x i8]* %20, metadata !479, metadata !DIExpression()) #7, !dbg !554
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(48) %120, i8* noundef nonnull align 1 dereferenceable(48) getelementptr inbounds ([48 x i8], [48 x i8]* @__const.nat64_handle_v4.____fmt.2, i64 0, i64 0), i64 48, i1 false) #7, !dbg !554
  call void @llvm.dbg.value(metadata i8* %63, metadata !446, metadata !DIExpression()) #7, !dbg !487
  %121 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* nonnull %120, i32 48, i8* nonnull %91, i8* nonnull %114) #7, !dbg !554
  call void @llvm.lifetime.end.p0i8(i64 48, i8* nonnull %120) #7, !dbg !555
  %122 = getelementptr inbounds i8, i8* %63, i64 12, !dbg !556
  %123 = bitcast i8* %122 to i32*, !dbg !556
  %124 = load i32, i32* %123, align 4, !dbg !556, !tbaa !557
  call void @llvm.dbg.value(metadata i32 %124, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 160, 32)) #7, !dbg !487
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(16) %71, i8* noundef nonnull align 4 dereferenceable(16) %114, i64 16, i1 false) #7, !dbg !558, !tbaa.struct !491
  %125 = getelementptr inbounds i8, i8* %63, i64 9, !dbg !559
  %126 = load i8, i8* %125, align 1, !dbg !559, !tbaa !560
  call void @llvm.dbg.value(metadata i8 %126, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 48, 8)) #7, !dbg !487
  %127 = getelementptr inbounds i8, i8* %63, i64 8, !dbg !561
  %128 = load i8, i8* %127, align 4, !dbg !561, !tbaa !562
  call void @llvm.dbg.value(metadata i8 %128, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 56, 8)) #7, !dbg !487
  %129 = getelementptr inbounds i8, i8* %63, i64 1, !dbg !563
  %130 = load i8, i8* %129, align 1, !dbg !563, !tbaa !564
  %131 = lshr i8 %130, 4, !dbg !565
  %132 = and i8 %131, 7, !dbg !565
  %133 = or i8 %132, 96, !dbg !566
  call void @llvm.dbg.value(metadata i8 %133, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 8)) #7, !dbg !487
  %134 = shl i8 %130, 4, !dbg !567
  call void @llvm.dbg.value(metadata i8 %134, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 8, 8)) #7, !dbg !487
  %135 = getelementptr inbounds i8, i8* %63, i64 2, !dbg !568
  %136 = bitcast i8* %135 to i16*, !dbg !568
  %137 = load i16, i16* %136, align 2, !dbg !568, !tbaa !569
  %138 = call i16 @llvm.bswap.i16(i16 %137) #7, !dbg !568
  %139 = add i16 %138, -20, !dbg !568
  %140 = call i16 @llvm.bswap.i16(i16 %139) #7, !dbg !568
  call void @llvm.dbg.value(metadata i16 %140, metadata !416, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 16)) #7, !dbg !487
  %141 = call i64 inttoptr (i64 31 to i64 (%struct.__sk_buff*, i16, i64)*)(%struct.__sk_buff* nonnull %0, i16 zeroext -8826, i64 0) #7, !dbg !570
  %142 = icmp eq i64 %141, 0, !dbg !570
  br i1 %142, label %143, label %177, !dbg !572

143:                                              ; preds = %119
  %144 = load i32, i32* %25, align 4, !dbg !573, !tbaa !346
  %145 = zext i32 %144 to i64, !dbg !574
  %146 = inttoptr i64 %145 to i8*, !dbg !575
  call void @llvm.dbg.value(metadata i8* %146, metadata !424, metadata !DIExpression()) #7, !dbg !487
  %147 = load i32, i32* %21, align 8, !dbg !576, !tbaa !337
  %148 = zext i32 %147 to i64, !dbg !577
  call void @llvm.dbg.value(metadata i64 %148, metadata !423, metadata !DIExpression()) #7, !dbg !487
  %149 = inttoptr i64 %145 to %struct.ethhdr*, !dbg !578
  call void @llvm.dbg.value(metadata %struct.ethhdr* %149, metadata !463, metadata !DIExpression()) #7, !dbg !487
  %150 = zext i32 %75 to i64
  %151 = getelementptr i8, i8* %146, i64 %150, !dbg !579
  call void @llvm.dbg.value(metadata i8* %151, metadata !429, metadata !DIExpression()) #7, !dbg !487
  %152 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %149, i64 1, !dbg !580
  %153 = inttoptr i64 %148 to %struct.ethhdr*, !dbg !582
  %154 = icmp ugt %struct.ethhdr* %152, %153, !dbg !583
  br i1 %154, label %177, label %155, !dbg !584

155:                                              ; preds = %143
  call void @llvm.dbg.value(metadata i64 %148, metadata !423, metadata !DIExpression()) #7, !dbg !487
  %156 = getelementptr inbounds i8, i8* %151, i64 40, !dbg !585
  %157 = bitcast i8* %156 to %struct.ipv6hdr*, !dbg !585
  %158 = inttoptr i64 %148 to %struct.ipv6hdr*, !dbg !586
  %159 = icmp ugt %struct.ipv6hdr* %157, %158, !dbg !587
  br i1 %159, label %177, label %160, !dbg !588

160:                                              ; preds = %155
  %161 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %149, i64 0, i32 2, !dbg !589
  store i16 -8826, i16* %161, align 1, !dbg !590, !tbaa !591
  store i8 %133, i8* %151, align 4, !dbg !593, !tbaa.struct !594
  %162 = getelementptr inbounds i8, i8* %151, i64 1, !dbg !593
  store i8 %134, i8* %162, align 1, !dbg !593, !tbaa.struct !595
  %163 = getelementptr inbounds i8, i8* %151, i64 2, !dbg !593
  %164 = bitcast i8* %163 to i16*, !dbg !593
  store i16 0, i16* %164, align 2, !dbg !593
  %165 = getelementptr inbounds i8, i8* %151, i64 4, !dbg !593
  %166 = bitcast i8* %165 to i16*, !dbg !593
  store i16 %140, i16* %166, align 4, !dbg !593, !tbaa.struct !596
  %167 = getelementptr inbounds i8, i8* %151, i64 6, !dbg !593
  store i8 %126, i8* %167, align 2, !dbg !593, !tbaa.struct !597
  %168 = getelementptr inbounds i8, i8* %151, i64 7, !dbg !593
  store i8 %128, i8* %168, align 1, !dbg !593, !tbaa.struct !598
  %169 = getelementptr inbounds i8, i8* %151, i64 8, !dbg !593
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(12) %169, i8* noundef nonnull align 4 dereferenceable(12) %70, i64 12, i1 false) #7, !dbg !593, !tbaa.struct !599
  %170 = getelementptr inbounds i8, i8* %151, i64 20, !dbg !593
  %171 = bitcast i8* %170 to i32*, !dbg !593
  store i32 %124, i32* %171, align 4, !dbg !593, !tbaa.struct !600
  %172 = getelementptr inbounds i8, i8* %151, i64 24, !dbg !593
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(16) %172, i8* noundef nonnull align 4 dereferenceable(16) %71, i64 16, i1 false) #7, !dbg !593, !tbaa.struct !491
  %173 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 10, !dbg !601
  %174 = load i32, i32* %173, align 8, !dbg !601, !tbaa !602
  %175 = call i64 inttoptr (i64 152 to i64 (i32, %struct.bpf_redir_neigh*, i32, i64)*)(i32 %174, %struct.bpf_redir_neigh* null, i32 0, i64 0) #7, !dbg !603
  %176 = trunc i64 %175 to i32, !dbg !603
  call void @llvm.dbg.value(metadata i32 %176, metadata !445, metadata !DIExpression()) #7, !dbg !487
  br label %177, !dbg !604

177:                                              ; preds = %68, %78, %82, %86, %90, %109, %116, %119, %143, %155, %160
  %178 = phi i32 [ 0, %90 ], [ 2, %109 ], [ 2, %119 ], [ 2, %143 ], [ 2, %155 ], [ %176, %160 ], [ 2, %116 ], [ 0, %68 ], [ 0, %78 ], [ 0, %82 ], [ 0, %86 ], !dbg !487
  call void @llvm.dbg.value(metadata i32 %178, metadata !445, metadata !DIExpression()) #7, !dbg !487
  call void @llvm.dbg.label(metadata !484) #7, !dbg !605
  call void @llvm.lifetime.end.p0i8(i64 12, i8* nonnull %70), !dbg !606
  call void @llvm.lifetime.end.p0i8(i64 16, i8* nonnull %71), !dbg !606
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %69) #7, !dbg !606
  br label %422, !dbg !607

179:                                              ; preds = %62
  call void @llvm.dbg.value(metadata i16 %64, metadata !334, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !335
  %180 = icmp ne i16 %64, -8826, !dbg !608
  %181 = select i1 %180, i1 true, i1 %1, !dbg !610
  br i1 %181, label %422, label %182, !dbg !610

182:                                              ; preds = %179
  call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !611, metadata !DIExpression()) #7, !dbg !683
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !614, metadata !DIExpression()) #7, !dbg !683
  call void @llvm.dbg.value(metadata i8* %24, metadata !615, metadata !DIExpression()) #7, !dbg !683
  call void @llvm.dbg.value(metadata i32 %26, metadata !616, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !683
  %183 = bitcast %struct.v6_trie_key* %3 to i8*, !dbg !685
  call void @llvm.lifetime.start.p0i8(i64 20, i8* nonnull %183) #7, !dbg !685
  call void @llvm.dbg.declare(metadata %struct.v6_trie_key* %3, metadata !617, metadata !DIExpression()) #7, !dbg !686
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(20) %183, i8* noundef nonnull align 4 dereferenceable(20) bitcast (%struct.v6_trie_key* @__const.nat64_handle_v6.saddr_key to i8*), i64 20, i1 false) #7, !dbg !686
  %184 = bitcast %struct.in6_addr* %4 to i8*, !dbg !687
  call void @llvm.lifetime.start.p0i8(i64 16, i8* nonnull %184) #7, !dbg !687
  call void @llvm.dbg.declare(metadata %struct.in6_addr* %4, metadata !628, metadata !DIExpression()) #7, !dbg !688
  call void @llvm.memset.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(16) %184, i8 0, i64 16, i1 false) #7, !dbg !688
  %185 = bitcast i32* %5 to i8*, !dbg !689
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %185) #7, !dbg !689
  %186 = bitcast i32* %6 to i8*, !dbg !689
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %186) #7, !dbg !689
  call void @llvm.dbg.value(metadata i32 0, metadata !635, metadata !DIExpression()) #7, !dbg !683
  %187 = getelementptr inbounds %struct.iphdr, %struct.iphdr* %7, i64 0, i32 0, !dbg !690
  call void @llvm.lifetime.start.p0i8(i64 20, i8* nonnull %187) #7, !dbg !690
  call void @llvm.dbg.declare(metadata %struct.iphdr* %7, metadata !639, metadata !DIExpression()) #7, !dbg !691
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(20) %187, i8* noundef nonnull align 4 dereferenceable(20) getelementptr inbounds (%struct.iphdr, %struct.iphdr* @__const.nat64_handle_v6.dst_hdr, i64 0, i32 0), i64 20, i1 false) #7, !dbg !691
  %188 = ptrtoint i8* %63 to i64, !dbg !692
  %189 = trunc i64 %188 to i32, !dbg !693
  %190 = sub i32 %189, %26, !dbg !693
  %191 = and i32 %190, 8191, !dbg !693
  call void @llvm.dbg.value(metadata i32 %191, metadata !633, metadata !DIExpression()) #7, !dbg !683
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !694, metadata !DIExpression()) #7, !dbg !703
  call void @llvm.dbg.value(metadata i8* %24, metadata !700, metadata !DIExpression()) #7, !dbg !703
  call void @llvm.dbg.value(metadata %struct.ipv6hdr** undef, metadata !701, metadata !DIExpression()) #7, !dbg !703
  call void @llvm.dbg.value(metadata i8* %63, metadata !702, metadata !DIExpression()) #7, !dbg !703
  %192 = getelementptr inbounds i8, i8* %63, i64 40, !dbg !705
  %193 = icmp ugt i8* %192, %24, !dbg !707
  br i1 %193, label %420, label %194, !dbg !708

194:                                              ; preds = %182
  %195 = load i8, i8* %63, align 4, !dbg !709
  %196 = and i8 %195, -16, !dbg !711
  %197 = icmp eq i8 %196, 96, !dbg !711
  br i1 %197, label %198, label %420, !dbg !712

198:                                              ; preds = %194
  call void @llvm.dbg.value(metadata i8* %192, metadata !318, metadata !DIExpression()), !dbg !335
  %199 = getelementptr inbounds i8, i8* %63, i64 6, !dbg !713
  %200 = load i8, i8* %199, align 2, !dbg !713, !tbaa !714
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !716, metadata !DIExpression()) #7, !dbg !733
  call void @llvm.dbg.value(metadata i8* %24, metadata !721, metadata !DIExpression()) #7, !dbg !733
  call void @llvm.dbg.value(metadata i32 0, metadata !723, metadata !DIExpression()) #7, !dbg !735
  call void @llvm.dbg.value(metadata i8 %200, metadata !722, metadata !DIExpression()) #7, !dbg !733
  call void @llvm.dbg.value(metadata i8* %192, metadata !725, metadata !DIExpression()) #7, !dbg !736
  %201 = getelementptr inbounds i8, i8* %63, i64 42, !dbg !737
  %202 = icmp ugt i8* %201, %24, !dbg !739
  br i1 %202, label %420, label %203, !dbg !740

203:                                              ; preds = %198
  switch i8 %200, label %278 [
    i8 0, label %205
    i8 60, label %205
    i8 43, label %205
    i8 -121, label %205
    i8 51, label %204
    i8 44, label %212
  ], !dbg !741

204:                                              ; preds = %203
  call void @llvm.dbg.value(metadata i8 undef, metadata !722, metadata !DIExpression()) #7, !dbg !733
  br label %205, !dbg !742

205:                                              ; preds = %204, %203, %203, %203, %203
  %206 = phi i64 [ 2, %204 ], [ 3, %203 ], [ 3, %203 ], [ 3, %203 ], [ 3, %203 ]
  %207 = getelementptr inbounds i8, i8* %63, i64 41, !dbg !744
  %208 = load i8, i8* %207, align 1, !dbg !744, !tbaa !745
  %209 = zext i8 %208 to i64, !dbg !744
  %210 = shl nuw nsw i64 %209, %206, !dbg !744
  %211 = add nuw nsw i64 %210, 8, !dbg !744
  br label %212, !dbg !744

212:                                              ; preds = %205, %203
  %213 = phi i64 [ 8, %203 ], [ %211, %205 ]
  %214 = getelementptr inbounds i8, i8* %192, i64 %213, !dbg !744
  call void @llvm.dbg.value(metadata i8* %214, metadata !318, metadata !DIExpression()), !dbg !335
  %215 = load i8, i8* %192, align 1, !dbg !744, !tbaa !747
  call void @llvm.dbg.value(metadata i32 1, metadata !723, metadata !DIExpression()) #7, !dbg !735
  call void @llvm.dbg.value(metadata i8 %215, metadata !722, metadata !DIExpression()) #7, !dbg !733
  call void @llvm.dbg.value(metadata i8* %214, metadata !725, metadata !DIExpression()) #7, !dbg !736
  %216 = getelementptr inbounds i8, i8* %214, i64 2, !dbg !737
  %217 = icmp ugt i8* %216, %24, !dbg !739
  br i1 %217, label %420, label %218, !dbg !740

218:                                              ; preds = %212
  switch i8 %215, label %278 [
    i8 0, label %219
    i8 60, label %219
    i8 43, label %219
    i8 -121, label %219
    i8 51, label %220
    i8 44, label %227
  ], !dbg !741

219:                                              ; preds = %218, %218, %218, %218
  call void @llvm.dbg.value(metadata i8 undef, metadata !722, metadata !DIExpression()) #7, !dbg !733
  br label %220, !dbg !748

220:                                              ; preds = %219, %218
  %221 = phi i64 [ 3, %219 ], [ 2, %218 ]
  %222 = getelementptr inbounds i8, i8* %214, i64 1, !dbg !744
  %223 = load i8, i8* %222, align 1, !dbg !744, !tbaa !745
  %224 = zext i8 %223 to i64, !dbg !744
  %225 = shl nuw nsw i64 %224, %221, !dbg !744
  %226 = add nuw nsw i64 %225, 8, !dbg !744
  br label %227, !dbg !744

227:                                              ; preds = %220, %218
  %228 = phi i64 [ 8, %218 ], [ %226, %220 ]
  %229 = getelementptr inbounds i8, i8* %214, i64 %228, !dbg !744
  call void @llvm.dbg.value(metadata i8* %229, metadata !318, metadata !DIExpression()), !dbg !335
  %230 = load i8, i8* %214, align 1, !dbg !744, !tbaa !747
  call void @llvm.dbg.value(metadata i32 2, metadata !723, metadata !DIExpression()) #7, !dbg !735
  call void @llvm.dbg.value(metadata i8 %230, metadata !722, metadata !DIExpression()) #7, !dbg !733
  call void @llvm.dbg.value(metadata i8* %229, metadata !725, metadata !DIExpression()) #7, !dbg !736
  %231 = getelementptr inbounds i8, i8* %229, i64 2, !dbg !737
  %232 = icmp ugt i8* %231, %24, !dbg !739
  br i1 %232, label %420, label %233, !dbg !740

233:                                              ; preds = %227
  switch i8 %230, label %278 [
    i8 0, label %234
    i8 60, label %234
    i8 43, label %234
    i8 -121, label %234
    i8 51, label %235
    i8 44, label %242
  ], !dbg !741

234:                                              ; preds = %233, %233, %233, %233
  call void @llvm.dbg.value(metadata i8 undef, metadata !722, metadata !DIExpression()) #7, !dbg !733
  br label %235, !dbg !748

235:                                              ; preds = %234, %233
  %236 = phi i64 [ 3, %234 ], [ 2, %233 ]
  %237 = getelementptr inbounds i8, i8* %229, i64 1, !dbg !744
  %238 = load i8, i8* %237, align 1, !dbg !744, !tbaa !745
  %239 = zext i8 %238 to i64, !dbg !744
  %240 = shl nuw nsw i64 %239, %236, !dbg !744
  %241 = add nuw nsw i64 %240, 8, !dbg !744
  br label %242, !dbg !744

242:                                              ; preds = %235, %233
  %243 = phi i64 [ 8, %233 ], [ %241, %235 ]
  %244 = getelementptr inbounds i8, i8* %229, i64 %243, !dbg !744
  call void @llvm.dbg.value(metadata i8* %244, metadata !318, metadata !DIExpression()), !dbg !335
  %245 = load i8, i8* %229, align 1, !dbg !744, !tbaa !747
  call void @llvm.dbg.value(metadata i32 3, metadata !723, metadata !DIExpression()) #7, !dbg !735
  call void @llvm.dbg.value(metadata i8 %245, metadata !722, metadata !DIExpression()) #7, !dbg !733
  call void @llvm.dbg.value(metadata i8* %244, metadata !725, metadata !DIExpression()) #7, !dbg !736
  %246 = getelementptr inbounds i8, i8* %244, i64 2, !dbg !737
  %247 = icmp ugt i8* %246, %24, !dbg !739
  br i1 %247, label %420, label %248, !dbg !740

248:                                              ; preds = %242
  switch i8 %245, label %278 [
    i8 0, label %249
    i8 60, label %249
    i8 43, label %249
    i8 -121, label %249
    i8 51, label %250
    i8 44, label %257
  ], !dbg !741

249:                                              ; preds = %248, %248, %248, %248
  call void @llvm.dbg.value(metadata i8 undef, metadata !722, metadata !DIExpression()) #7, !dbg !733
  br label %250, !dbg !748

250:                                              ; preds = %249, %248
  %251 = phi i64 [ 3, %249 ], [ 2, %248 ]
  %252 = getelementptr inbounds i8, i8* %244, i64 1, !dbg !744
  %253 = load i8, i8* %252, align 1, !dbg !744, !tbaa !745
  %254 = zext i8 %253 to i64, !dbg !744
  %255 = shl nuw nsw i64 %254, %251, !dbg !744
  %256 = add nuw nsw i64 %255, 8, !dbg !744
  br label %257, !dbg !744

257:                                              ; preds = %250, %248
  %258 = phi i64 [ 8, %248 ], [ %256, %250 ]
  %259 = getelementptr inbounds i8, i8* %244, i64 %258, !dbg !744
  call void @llvm.dbg.value(metadata i8* %259, metadata !318, metadata !DIExpression()), !dbg !335
  %260 = load i8, i8* %244, align 1, !dbg !744, !tbaa !747
  call void @llvm.dbg.value(metadata i32 4, metadata !723, metadata !DIExpression()) #7, !dbg !735
  call void @llvm.dbg.value(metadata i8 %260, metadata !722, metadata !DIExpression()) #7, !dbg !733
  call void @llvm.dbg.value(metadata i8* %259, metadata !725, metadata !DIExpression()) #7, !dbg !736
  %261 = getelementptr inbounds i8, i8* %259, i64 2, !dbg !737
  %262 = icmp ugt i8* %261, %24, !dbg !739
  br i1 %262, label %420, label %263, !dbg !740

263:                                              ; preds = %257
  switch i8 %260, label %278 [
    i8 0, label %264
    i8 60, label %264
    i8 43, label %264
    i8 -121, label %264
    i8 51, label %265
    i8 44, label %272
  ], !dbg !741

264:                                              ; preds = %263, %263, %263, %263
  call void @llvm.dbg.value(metadata i8 undef, metadata !722, metadata !DIExpression()) #7, !dbg !733
  br label %265, !dbg !748

265:                                              ; preds = %264, %263
  %266 = phi i64 [ 3, %264 ], [ 2, %263 ]
  %267 = getelementptr inbounds i8, i8* %259, i64 1, !dbg !744
  %268 = load i8, i8* %267, align 1, !dbg !744, !tbaa !745
  %269 = zext i8 %268 to i64, !dbg !744
  %270 = shl nuw nsw i64 %269, %266, !dbg !744
  %271 = add nuw nsw i64 %270, 10, !dbg !744
  br label %272, !dbg !744

272:                                              ; preds = %265, %263
  %273 = phi i64 [ 10, %263 ], [ %271, %265 ]
  call void @llvm.dbg.value(metadata !DIArgList(i8* %259, i64 undef), metadata !318, metadata !DIExpression(DW_OP_LLVM_arg, 0, DW_OP_LLVM_arg, 1, DW_OP_constu, 1, DW_OP_mul, DW_OP_plus, DW_OP_stack_value)), !dbg !335
  %274 = load i8, i8* %259, align 1, !dbg !744, !tbaa !747
  call void @llvm.dbg.value(metadata i32 5, metadata !723, metadata !DIExpression()) #7, !dbg !735
  call void @llvm.dbg.value(metadata i8 %274, metadata !722, metadata !DIExpression()) #7, !dbg !733
  call void @llvm.dbg.value(metadata !DIArgList(i8* %259, i64 undef), metadata !725, metadata !DIExpression(DW_OP_LLVM_arg, 0, DW_OP_LLVM_arg, 1, DW_OP_constu, 1, DW_OP_mul, DW_OP_plus, DW_OP_stack_value)) #7, !dbg !736
  %275 = getelementptr inbounds i8, i8* %259, i64 %273, !dbg !737
  %276 = icmp ugt i8* %275, %24, !dbg !739
  br i1 %276, label %420, label %277, !dbg !740

277:                                              ; preds = %272
  switch i8 %274, label %278 [
    i8 0, label %420
    i8 60, label %420
    i8 43, label %420
    i8 -121, label %420
    i8 51, label %420
    i8 44, label %420
  ], !dbg !741

278:                                              ; preds = %277, %263, %248, %233, %218, %203
  %279 = phi i8 [ %200, %203 ], [ %215, %218 ], [ %230, %233 ], [ %245, %248 ], [ %260, %263 ], [ %274, %277 ]
  call void @llvm.dbg.value(metadata i8 %279, metadata !632, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !683
  call void @llvm.dbg.value(metadata i8* %63, metadata !634, metadata !DIExpression()) #7, !dbg !683
  %280 = getelementptr inbounds i8, i8* %63, i64 24, !dbg !749
  call void @llvm.dbg.value(metadata i8* %280, metadata !627, metadata !DIExpression()) #7, !dbg !683
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(16) %184, i8* noundef nonnull align 4 dereferenceable(16) %280, i64 12, i1 false) #7, !dbg !750, !tbaa.struct !491
  %281 = getelementptr inbounds %struct.in6_addr, %struct.in6_addr* %4, i64 0, i32 0, i32 0, i64 3, !dbg !751
  store i32 0, i32* %281, align 4, !dbg !752, !tbaa !492
  call void @llvm.dbg.value(metadata %struct.in6_addr* %4, metadata !753, metadata !DIExpression()) #7, !dbg !760
  call void @llvm.dbg.value(metadata %struct.in6_addr* undef, metadata !758, metadata !DIExpression()) #7, !dbg !760
  call void @llvm.dbg.value(metadata i64 0, metadata !759, metadata !DIExpression()) #7, !dbg !760
  %282 = getelementptr inbounds %struct.in6_addr, %struct.in6_addr* %4, i64 0, i32 0, i32 0, i64 0, !dbg !762
  %283 = load i32, i32* %282, align 4, !dbg !762, !tbaa !492
  %284 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 0, i32 0, i32 0, i64 0), align 8, !dbg !767, !tbaa !492
  %285 = icmp eq i32 %283, %284, !dbg !768
  call void @llvm.dbg.value(metadata i64 0, metadata !759, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !760
  br i1 %285, label %286, label %299, !dbg !768

286:                                              ; preds = %278
  call void @llvm.dbg.value(metadata i64 1, metadata !759, metadata !DIExpression()) #7, !dbg !760
  %287 = getelementptr inbounds %struct.in6_addr, %struct.in6_addr* %4, i64 0, i32 0, i32 0, i64 1, !dbg !762
  %288 = load i32, i32* %287, align 4, !dbg !762, !tbaa !492
  %289 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 0, i32 0, i32 0, i64 1), align 4, !dbg !767, !tbaa !492
  %290 = icmp eq i32 %288, %289, !dbg !768
  call void @llvm.dbg.value(metadata i64 1, metadata !759, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !760
  br i1 %290, label %291, label %299, !dbg !768

291:                                              ; preds = %286
  call void @llvm.dbg.value(metadata i64 2, metadata !759, metadata !DIExpression()) #7, !dbg !760
  %292 = getelementptr inbounds %struct.in6_addr, %struct.in6_addr* %4, i64 0, i32 0, i32 0, i64 2, !dbg !762
  %293 = load i32, i32* %292, align 4, !dbg !762, !tbaa !492
  %294 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 0, i32 0, i32 0, i64 2), align 8, !dbg !767, !tbaa !492
  %295 = icmp ne i32 %293, %294, !dbg !768
  call void @llvm.dbg.value(metadata i64 2, metadata !759, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !760
  %296 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 0, i32 0, i32 0, i64 3), align 4
  %297 = icmp ne i32 %296, 0
  %298 = select i1 %295, i1 true, i1 %297, !dbg !768
  call void @llvm.dbg.value(metadata i64 3, metadata !759, metadata !DIExpression()) #7, !dbg !760
  br i1 %298, label %299, label %302, !dbg !768

299:                                              ; preds = %291, %286, %278
  %300 = getelementptr inbounds [60 x i8], [60 x i8]* %8, i64 0, i64 0, !dbg !769
  call void @llvm.lifetime.start.p0i8(i64 60, i8* nonnull %300) #7, !dbg !769
  call void @llvm.dbg.declare(metadata [60 x i8]* %8, metadata !640, metadata !DIExpression()) #7, !dbg !769
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(60) %300, i8* noundef nonnull align 1 dereferenceable(60) getelementptr inbounds ([60 x i8], [60 x i8]* @__const.nat64_handle_v6.____fmt, i64 0, i64 0), i64 60, i1 false) #7, !dbg !769
  %301 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* nonnull %300, i32 60, %struct.in6_addr* nonnull %4, %struct.in6_addr* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 0)) #7, !dbg !769
  call void @llvm.lifetime.end.p0i8(i64 60, i8* nonnull %300) #7, !dbg !770
  br label %420, !dbg !771

302:                                              ; preds = %291
  call void @llvm.dbg.value(metadata i64 3, metadata !759, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !760
  call void @llvm.dbg.value(metadata i32 2, metadata !635, metadata !DIExpression()) #7, !dbg !683
  call void @llvm.dbg.value(metadata i8* %63, metadata !634, metadata !DIExpression()) #7, !dbg !683
  %303 = load i8, i8* %199, align 2, !dbg !772, !tbaa !714
  %304 = icmp eq i8 %279, %303, !dbg !773
  br i1 %304, label %309, label %305, !dbg !774

305:                                              ; preds = %302
  %306 = getelementptr inbounds [55 x i8], [55 x i8]* %9, i64 0, i64 0, !dbg !775
  call void @llvm.lifetime.start.p0i8(i64 55, i8* nonnull %306) #7, !dbg !775
  call void @llvm.dbg.declare(metadata [55 x i8]* %9, metadata !647, metadata !DIExpression()) #7, !dbg !775
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(55) %306, i8* noundef nonnull align 1 dereferenceable(55) getelementptr inbounds ([55 x i8], [55 x i8]* @__const.nat64_handle_v6.____fmt.3, i64 0, i64 0), i64 55, i1 false) #7, !dbg !775
  call void @llvm.dbg.value(metadata i8* %63, metadata !634, metadata !DIExpression()) #7, !dbg !683
  %307 = getelementptr inbounds i8, i8* %63, i64 8, !dbg !775
  %308 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* nonnull %306, i32 55, i8* nonnull %307) #7, !dbg !775
  call void @llvm.lifetime.end.p0i8(i64 55, i8* nonnull %306) #7, !dbg !776
  br label %420, !dbg !777

309:                                              ; preds = %302
  %310 = getelementptr inbounds i8, i8* %63, i64 36, !dbg !778
  %311 = bitcast i8* %310 to i32*, !dbg !778
  %312 = load i32, i32* %311, align 4, !dbg !778, !tbaa !492
  call void @llvm.dbg.value(metadata i32 %312, metadata !631, metadata !DIExpression()) #7, !dbg !683
  store i32 %312, i32* %6, align 4, !dbg !779, !tbaa !527
  %313 = icmp eq i32 %312, 0, !dbg !780
  %314 = and i32 %312, 255
  %315 = icmp eq i32 %314, 127
  %316 = or i1 %313, %315, !dbg !781
  %317 = and i32 %312, 240
  %318 = icmp eq i32 %317, 224
  %319 = or i1 %318, %316, !dbg !781
  br i1 %319, label %320, label %324, !dbg !781

320:                                              ; preds = %309
  %321 = getelementptr inbounds [52 x i8], [52 x i8]* %10, i64 0, i64 0, !dbg !782
  call void @llvm.lifetime.start.p0i8(i64 52, i8* nonnull %321) #7, !dbg !782
  call void @llvm.dbg.declare(metadata [52 x i8]* %10, metadata !654, metadata !DIExpression()) #7, !dbg !782
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(52) %321, i8* noundef nonnull align 1 dereferenceable(52) getelementptr inbounds ([52 x i8], [52 x i8]* @__const.nat64_handle_v6.____fmt.4, i64 0, i64 0), i64 52, i1 false) #7, !dbg !782
  call void @llvm.dbg.value(metadata i8* %63, metadata !634, metadata !DIExpression()) #7, !dbg !683
  %322 = getelementptr inbounds i8, i8* %63, i64 8, !dbg !782
  call void @llvm.dbg.value(metadata i32* %6, metadata !631, metadata !DIExpression(DW_OP_deref)) #7, !dbg !683
  %323 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* nonnull %321, i32 52, i32* nonnull %6, i8* nonnull %322) #7, !dbg !782
  call void @llvm.lifetime.end.p0i8(i64 52, i8* nonnull %321) #7, !dbg !783
  br label %420, !dbg !784

324:                                              ; preds = %309
  %325 = getelementptr inbounds %struct.v6_trie_key, %struct.v6_trie_key* %3, i64 0, i32 1, !dbg !785
  call void @llvm.dbg.value(metadata i8* %63, metadata !634, metadata !DIExpression()) #7, !dbg !683
  %326 = getelementptr inbounds i8, i8* %63, i64 8, !dbg !786
  %327 = bitcast i8* %326 to %struct.in6_addr*, !dbg !786
  %328 = bitcast %struct.in6_addr* %325 to i8*, !dbg !786
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(16) %328, i8* noundef nonnull align 4 dereferenceable(16) %326, i64 16, i1 false) #7, !dbg !786, !tbaa.struct !491
  %329 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.anon.6* @allowed_v6_src to i8*), i8* nonnull %183) #7, !dbg !787
  call void @llvm.dbg.value(metadata i8* %329, metadata !629, metadata !DIExpression()) #7, !dbg !683
  %330 = icmp eq i8* %329, null, !dbg !788
  br i1 %330, label %331, label %334, !dbg !789

331:                                              ; preds = %324
  %332 = getelementptr inbounds [43 x i8], [43 x i8]* %11, i64 0, i64 0, !dbg !790
  call void @llvm.lifetime.start.p0i8(i64 43, i8* nonnull %332) #7, !dbg !790
  call void @llvm.dbg.declare(metadata [43 x i8]* %11, metadata !661, metadata !DIExpression()) #7, !dbg !790
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(43) %332, i8* noundef nonnull align 1 dereferenceable(43) getelementptr inbounds ([43 x i8], [43 x i8]* @__const.nat64_handle_v6.____fmt.5, i64 0, i64 0), i64 43, i1 false) #7, !dbg !790
  call void @llvm.dbg.value(metadata i8* %63, metadata !634, metadata !DIExpression()) #7, !dbg !683
  %333 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* nonnull %332, i32 43, i8* nonnull %326) #7, !dbg !790
  call void @llvm.lifetime.end.p0i8(i64 43, i8* nonnull %332) #7, !dbg !791
  br label %420, !dbg !792

334:                                              ; preds = %324
  call void @llvm.dbg.value(metadata i8* %63, metadata !634, metadata !DIExpression()) #7, !dbg !683
  %335 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.anon.4* @v6_state_map to i8*), i8* nonnull %326) #7, !dbg !793
  call void @llvm.dbg.value(metadata i8* %335, metadata !638, metadata !DIExpression()) #7, !dbg !683
  %336 = icmp eq i8* %335, null, !dbg !794
  br i1 %336, label %337, label %349, !dbg !795

337:                                              ; preds = %334
  call void @llvm.dbg.value(metadata i8* %63, metadata !634, metadata !DIExpression()) #7, !dbg !683
  %338 = call fastcc %struct.v6_addr_state* @alloc_new_state(%struct.in6_addr* nonnull %327) #7, !dbg !796
  call void @llvm.dbg.value(metadata %struct.v6_addr_state* %338, metadata !638, metadata !DIExpression()) #7, !dbg !683
  %339 = icmp eq %struct.v6_addr_state* %338, null, !dbg !797
  br i1 %339, label %340, label %343, !dbg !798

340:                                              ; preds = %337
  %341 = getelementptr inbounds [51 x i8], [51 x i8]* %12, i64 0, i64 0, !dbg !799
  call void @llvm.lifetime.start.p0i8(i64 51, i8* nonnull %341) #7, !dbg !799
  call void @llvm.dbg.declare(metadata [51 x i8]* %12, metadata !668, metadata !DIExpression()) #7, !dbg !799
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(51) %341, i8* noundef nonnull align 1 dereferenceable(51) getelementptr inbounds ([51 x i8], [51 x i8]* @__const.nat64_handle_v6.____fmt.6, i64 0, i64 0), i64 51, i1 false) #7, !dbg !799
  call void @llvm.dbg.value(metadata i8* %63, metadata !634, metadata !DIExpression()) #7, !dbg !683
  %342 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* nonnull %341, i32 51, i8* nonnull %326) #7, !dbg !799
  call void @llvm.lifetime.end.p0i8(i64 51, i8* nonnull %341) #7, !dbg !800
  br label %420, !dbg !801

343:                                              ; preds = %337
  %344 = getelementptr inbounds %struct.v6_addr_state, %struct.v6_addr_state* %338, i64 0, i32 1, !dbg !802
  %345 = load i32, i32* %344, align 8, !dbg !802, !tbaa !803
  %346 = call i32 @llvm.bswap.i32(i32 %345) #7, !dbg !802
  call void @llvm.dbg.value(metadata i32 %346, metadata !630, metadata !DIExpression()) #7, !dbg !683
  store i32 %346, i32* %5, align 4, !dbg !805, !tbaa !527
  %347 = getelementptr inbounds [51 x i8], [51 x i8]* %13, i64 0, i64 0, !dbg !806
  call void @llvm.lifetime.start.p0i8(i64 51, i8* nonnull %347) #7, !dbg !806
  call void @llvm.dbg.declare(metadata [51 x i8]* %13, metadata !677, metadata !DIExpression()) #7, !dbg !806
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(51) %347, i8* noundef nonnull align 1 dereferenceable(51) getelementptr inbounds ([51 x i8], [51 x i8]* @__const.nat64_handle_v6.____fmt.7, i64 0, i64 0), i64 51, i1 false) #7, !dbg !806
  call void @llvm.dbg.value(metadata i8* %63, metadata !634, metadata !DIExpression()) #7, !dbg !683
  call void @llvm.dbg.value(metadata i32* %5, metadata !630, metadata !DIExpression(DW_OP_deref)) #7, !dbg !683
  %348 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* nonnull %347, i32 51, i8* nonnull %326, i32* nonnull %5) #7, !dbg !806
  call void @llvm.lifetime.end.p0i8(i64 51, i8* nonnull %347) #7, !dbg !807
  br label %360, !dbg !808

349:                                              ; preds = %334
  %350 = bitcast i8* %335 to %struct.v6_addr_state*, !dbg !793
  call void @llvm.dbg.value(metadata %struct.v6_addr_state* %350, metadata !638, metadata !DIExpression()) #7, !dbg !683
  %351 = call i64 inttoptr (i64 5 to i64 ()*)() #7, !dbg !809
  %352 = bitcast i8* %335 to i64*, !dbg !810
  store i64 %351, i64* %352, align 8, !dbg !811, !tbaa !812
  call void @llvm.dbg.value(metadata i8* %63, metadata !634, metadata !DIExpression()) #7, !dbg !683
  %353 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i8* bitcast (%struct.anon.4* @v6_state_map to i8*), i8* nonnull %326, i8* nonnull %335, i64 2) #7, !dbg !813
  %354 = getelementptr inbounds i8, i8* %335, i64 8, !dbg !814
  %355 = bitcast i8* %354 to i32*, !dbg !814
  %356 = load i32, i32* %355, align 8, !dbg !814, !tbaa !803
  %357 = call i32 @llvm.bswap.i32(i32 %356) #7, !dbg !814
  call void @llvm.dbg.value(metadata i32 %357, metadata !630, metadata !DIExpression()) #7, !dbg !683
  store i32 %357, i32* %5, align 4, !dbg !815, !tbaa !527
  %358 = getelementptr inbounds [51 x i8], [51 x i8]* %14, i64 0, i64 0, !dbg !816
  call void @llvm.lifetime.start.p0i8(i64 51, i8* nonnull %358) #7, !dbg !816
  call void @llvm.dbg.declare(metadata [51 x i8]* %14, metadata !679, metadata !DIExpression()) #7, !dbg !816
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(51) %358, i8* noundef nonnull align 1 dereferenceable(51) getelementptr inbounds ([51 x i8], [51 x i8]* @__const.nat64_handle_v6.____fmt.8, i64 0, i64 0), i64 51, i1 false) #7, !dbg !816
  call void @llvm.dbg.value(metadata i32* %5, metadata !630, metadata !DIExpression(DW_OP_deref)) #7, !dbg !683
  %359 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* nonnull %358, i32 51, i8* nonnull %326, i32* nonnull %5) #7, !dbg !816
  call void @llvm.lifetime.end.p0i8(i64 51, i8* nonnull %358) #7, !dbg !817
  br label %360

360:                                              ; preds = %349, %343
  %361 = phi %struct.v6_addr_state* [ %350, %349 ], [ %338, %343 ], !dbg !683
  call void @llvm.dbg.value(metadata %struct.v6_addr_state* %361, metadata !638, metadata !DIExpression()) #7, !dbg !683
  call void @llvm.dbg.value(metadata i32 %312, metadata !631, metadata !DIExpression()) #7, !dbg !683
  %362 = getelementptr inbounds %struct.iphdr, %struct.iphdr* %7, i64 0, i32 9, !dbg !818
  store i32 %312, i32* %362, align 4, !dbg !819, !tbaa !524
  %363 = getelementptr inbounds %struct.v6_addr_state, %struct.v6_addr_state* %361, i64 0, i32 1, !dbg !820
  %364 = load i32, i32* %363, align 8, !dbg !820, !tbaa !803
  %365 = call i32 @llvm.bswap.i32(i32 %364) #7, !dbg !820
  %366 = getelementptr inbounds %struct.iphdr, %struct.iphdr* %7, i64 0, i32 8, !dbg !821
  store i32 %365, i32* %366, align 4, !dbg !822, !tbaa !557
  call void @llvm.dbg.value(metadata i8* %63, metadata !634, metadata !DIExpression()) #7, !dbg !683
  %367 = load i8, i8* %199, align 2, !dbg !823, !tbaa !714
  %368 = getelementptr inbounds %struct.iphdr, %struct.iphdr* %7, i64 0, i32 6, !dbg !824
  store i8 %367, i8* %368, align 1, !dbg !825, !tbaa !560
  %369 = getelementptr inbounds i8, i8* %63, i64 7, !dbg !826
  %370 = load i8, i8* %369, align 1, !dbg !826, !tbaa !827
  %371 = getelementptr inbounds %struct.iphdr, %struct.iphdr* %7, i64 0, i32 5, !dbg !828
  store i8 %370, i8* %371, align 4, !dbg !829, !tbaa !562
  %372 = load i8, i8* %63, align 4, !dbg !830
  %373 = getelementptr inbounds i8, i8* %63, i64 1, !dbg !831
  %374 = load i8, i8* %373, align 1, !dbg !831, !tbaa !492
  %375 = call i8 @llvm.fshl.i8(i8 %372, i8 %374, i8 4) #7, !dbg !832
  %376 = getelementptr inbounds %struct.iphdr, %struct.iphdr* %7, i64 0, i32 1, !dbg !833
  store i8 %375, i8* %376, align 1, !dbg !834, !tbaa !564
  %377 = getelementptr inbounds i8, i8* %63, i64 4, !dbg !835
  %378 = bitcast i8* %377 to i16*, !dbg !835
  %379 = load i16, i16* %378, align 4, !dbg !835, !tbaa !836
  %380 = call i16 @llvm.bswap.i16(i16 %379) #7, !dbg !835
  %381 = add i16 %380, 20, !dbg !835
  %382 = call i16 @llvm.bswap.i16(i16 %381) #7, !dbg !835
  %383 = getelementptr inbounds %struct.iphdr, %struct.iphdr* %7, i64 0, i32 2, !dbg !837
  store i16 %382, i16* %383, align 2, !dbg !838, !tbaa !569
  %384 = bitcast %struct.iphdr* %7 to i32*, !dbg !839
  %385 = call i64 inttoptr (i64 28 to i64 (i32*, i32, i32*, i32, i32)*)(i32* nonnull %384, i32 0, i32* nonnull %384, i32 20, i32 0) #7, !dbg !840
  %386 = trunc i64 %385 to i32, !dbg !840
  call void @llvm.dbg.value(metadata i32 %386, metadata !841, metadata !DIExpression()) #7, !dbg !847
  %387 = lshr i32 %386, 16, !dbg !849
  %388 = and i32 %386, 65535, !dbg !850
  %389 = add nuw nsw i32 %387, %388, !dbg !851
  call void @llvm.dbg.value(metadata i32 %389, metadata !846, metadata !DIExpression()) #7, !dbg !847
  %390 = lshr i32 %389, 16, !dbg !852
  %391 = add nuw nsw i32 %390, %389, !dbg !853
  call void @llvm.dbg.value(metadata i32 %391, metadata !846, metadata !DIExpression()) #7, !dbg !847
  %392 = trunc i32 %391 to i16, !dbg !854
  %393 = xor i16 %392, -1, !dbg !854
  %394 = getelementptr inbounds %struct.iphdr, %struct.iphdr* %7, i64 0, i32 7, !dbg !855
  store i16 %393, i16* %394, align 2, !dbg !856, !tbaa !857
  %395 = call i64 inttoptr (i64 31 to i64 (%struct.__sk_buff*, i16, i64)*)(%struct.__sk_buff* nonnull %0, i16 zeroext 8, i64 0) #7, !dbg !858
  %396 = icmp eq i64 %395, 0, !dbg !858
  br i1 %396, label %397, label %420, !dbg !860

397:                                              ; preds = %360
  %398 = load i32, i32* %25, align 4, !dbg !861, !tbaa !346
  %399 = zext i32 %398 to i64, !dbg !862
  %400 = inttoptr i64 %399 to i8*, !dbg !863
  call void @llvm.dbg.value(metadata i8* %400, metadata !616, metadata !DIExpression()) #7, !dbg !683
  %401 = load i32, i32* %21, align 8, !dbg !864, !tbaa !337
  %402 = zext i32 %401 to i64, !dbg !865
  call void @llvm.dbg.value(metadata i64 %402, metadata !615, metadata !DIExpression()) #7, !dbg !683
  %403 = inttoptr i64 %399 to %struct.ethhdr*, !dbg !866
  call void @llvm.dbg.value(metadata %struct.ethhdr* %403, metadata !636, metadata !DIExpression()) #7, !dbg !683
  %404 = zext i32 %191 to i64
  %405 = getelementptr i8, i8* %400, i64 %404, !dbg !867
  call void @llvm.dbg.value(metadata i8* %405, metadata !637, metadata !DIExpression()) #7, !dbg !683
  %406 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %403, i64 1, !dbg !868
  %407 = inttoptr i64 %402 to %struct.ethhdr*, !dbg !870
  %408 = icmp ugt %struct.ethhdr* %406, %407, !dbg !871
  br i1 %408, label %420, label %409, !dbg !872

409:                                              ; preds = %397
  call void @llvm.dbg.value(metadata i64 %402, metadata !615, metadata !DIExpression()) #7, !dbg !683
  call void @llvm.dbg.value(metadata i8* %405, metadata !637, metadata !DIExpression()) #7, !dbg !683
  %410 = getelementptr inbounds i8, i8* %405, i64 20, !dbg !873
  %411 = bitcast i8* %410 to %struct.iphdr*, !dbg !873
  %412 = inttoptr i64 %402 to %struct.iphdr*, !dbg !874
  %413 = icmp ugt %struct.iphdr* %411, %412, !dbg !875
  br i1 %413, label %420, label %414, !dbg !876

414:                                              ; preds = %409
  %415 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %403, i64 0, i32 2, !dbg !877
  store i16 8, i16* %415, align 1, !dbg !878, !tbaa !591
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(20) %405, i8* noundef nonnull align 4 dereferenceable(20) %187, i64 20, i1 false) #7, !dbg !879, !tbaa.struct !880
  %416 = getelementptr inbounds %struct.__sk_buff, %struct.__sk_buff* %0, i64 0, i32 10, !dbg !881
  %417 = load i32, i32* %416, align 8, !dbg !881, !tbaa !602
  %418 = call i64 inttoptr (i64 23 to i64 (i32, i64)*)(i32 %417, i64 1) #7, !dbg !882
  %419 = trunc i64 %418 to i32, !dbg !882
  call void @llvm.dbg.value(metadata i32 %419, metadata !635, metadata !DIExpression()) #7, !dbg !683
  br label %420, !dbg !883

420:                                              ; preds = %277, %277, %277, %277, %277, %277, %182, %194, %198, %212, %227, %242, %257, %272, %299, %305, %320, %331, %340, %360, %397, %409, %414
  %421 = phi i32 [ 0, %299 ], [ 2, %305 ], [ 2, %320 ], [ 2, %360 ], [ 2, %397 ], [ 2, %409 ], [ %419, %414 ], [ 2, %340 ], [ 2, %331 ], [ 0, %182 ], [ 0, %194 ], [ 0, %272 ], [ 0, %257 ], [ 0, %242 ], [ 0, %227 ], [ 0, %212 ], [ 0, %198 ], [ 0, %277 ], [ 0, %277 ], [ 0, %277 ], [ 0, %277 ], [ 0, %277 ], [ 0, %277 ], !dbg !683
  call void @llvm.dbg.value(metadata i32 %421, metadata !635, metadata !DIExpression()) #7, !dbg !683
  call void @llvm.dbg.label(metadata !682) #7, !dbg !884
  call void @llvm.lifetime.end.p0i8(i64 20, i8* nonnull %187) #7, !dbg !885
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %186) #7, !dbg !885
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %185) #7, !dbg !885
  call void @llvm.lifetime.end.p0i8(i64 16, i8* nonnull %184) #7, !dbg !885
  call void @llvm.lifetime.end.p0i8(i64 20, i8* nonnull %183) #7, !dbg !885
  br label %422, !dbg !886

422:                                              ; preds = %2, %179, %420, %177
  %423 = phi i32 [ %178, %177 ], [ %421, %420 ], [ 0, %179 ], [ 0, %2 ], !dbg !335
  ret i32 %423, !dbg !887
}

; Function Attrs: nounwind
define dso_local i32 @nat64_ingress(%struct.__sk_buff* %0) #0 section "classifier" !dbg !888 {
  call void @llvm.dbg.value(metadata %struct.__sk_buff* %0, metadata !890, metadata !DIExpression()), !dbg !891
  %2 = tail call fastcc i32 @nat64_handler(%struct.__sk_buff* %0, i1 zeroext false), !dbg !892
  ret i32 %2, !dbg !893
}

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #2

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #2

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare i16 @llvm.bswap.i16(i16) #1

; Function Attrs: argmemonly mustprogress nofree nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg) #3

; Function Attrs: argmemonly mustprogress nofree nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly, i8* noalias nocapture readonly, i64, i1 immarg) #4

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare i32 @llvm.bswap.i32(i32) #1

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.label(metadata) #1

; Function Attrs: nounwind
define internal fastcc %struct.v6_addr_state* @alloc_new_state(%struct.in6_addr* %0) unnamed_addr #0 !dbg !894 {
  %2 = alloca i64, align 8
  %3 = alloca i32, align 4
  %4 = alloca %struct.v6_addr_state, align 8
  %5 = alloca i32, align 4
  call void @llvm.dbg.value(metadata %struct.in6_addr* %0, metadata !898, metadata !DIExpression()), !dbg !910
  %6 = bitcast %struct.v6_addr_state* %4 to i8*, !dbg !911
  call void @llvm.lifetime.start.p0i8(i64 16, i8* nonnull %6) #7, !dbg !911
  call void @llvm.dbg.declare(metadata %struct.v6_addr_state* %4, metadata !899, metadata !DIExpression()), !dbg !912
  %7 = getelementptr inbounds %struct.v6_addr_state, %struct.v6_addr_state* %4, i64 0, i32 0, !dbg !913
  %8 = tail call i64 inttoptr (i64 5 to i64 ()*)() #7, !dbg !914
  store i64 %8, i64* %7, align 8, !dbg !913, !tbaa !812
  %9 = getelementptr inbounds %struct.v6_addr_state, %struct.v6_addr_state* %4, i64 0, i32 1, !dbg !913
  store i32 0, i32* %9, align 8, !dbg !913, !tbaa !803
  %10 = getelementptr inbounds %struct.v6_addr_state, %struct.v6_addr_state* %4, i64 0, i32 2, !dbg !913
  store i32 0, i32* %10, align 4, !dbg !913, !tbaa !915
  %11 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 3), align 8, !dbg !916, !tbaa !535
  %12 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 4), align 4, !dbg !917, !tbaa !530
  %13 = xor i32 %12, -1, !dbg !918
  %14 = or i32 %11, %13, !dbg !919
  %15 = add i32 %14, -1, !dbg !920
  call void @llvm.dbg.value(metadata i32 %15, metadata !900, metadata !DIExpression()), !dbg !910
  %16 = bitcast i32* %5 to i8*, !dbg !921
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %16) #7, !dbg !921
  call void @llvm.dbg.value(metadata i32 0, metadata !901, metadata !DIExpression()), !dbg !910
  store i32 0, i32* %5, align 4, !dbg !922, !tbaa !527
  call void @llvm.dbg.value(metadata i32 0, metadata !902, metadata !DIExpression()), !dbg !910
  call void @llvm.dbg.value(metadata i32 0, metadata !902, metadata !DIExpression()), !dbg !910
  %17 = atomicrmw or i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 0 seq_cst, align 8, !dbg !923
  %18 = trunc i64 %17 to i32, !dbg !923
  call void @llvm.dbg.value(metadata i32 %18, metadata !907, metadata !DIExpression()), !dbg !924
  %19 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 3), align 8, !dbg !925, !tbaa !535
  %20 = add i32 %19, %18, !dbg !926
  call void @llvm.dbg.value(metadata i32 %20, metadata !903, metadata !DIExpression()), !dbg !924
  %21 = icmp ult i32 %20, %15, !dbg !927
  br i1 %21, label %46, label %28, !dbg !929

22:                                               ; preds = %46
  call void @llvm.dbg.value(metadata i32 1, metadata !902, metadata !DIExpression()), !dbg !910
  call void @llvm.dbg.value(metadata i32 0, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  call void @llvm.dbg.value(metadata i32 1, metadata !902, metadata !DIExpression()), !dbg !910
  %23 = atomicrmw or i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 0 seq_cst, align 8, !dbg !923
  %24 = trunc i64 %23 to i32, !dbg !923
  call void @llvm.dbg.value(metadata i32 %24, metadata !907, metadata !DIExpression()), !dbg !924
  %25 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 3), align 8, !dbg !925, !tbaa !535
  %26 = add i32 %25, %24, !dbg !926
  call void @llvm.dbg.value(metadata i32 %26, metadata !903, metadata !DIExpression()), !dbg !924
  %27 = icmp ult i32 %26, %15, !dbg !927
  br i1 %27, label %73, label %28, !dbg !929

28:                                               ; preds = %163, %151, %139, %127, %115, %103, %91, %79, %22, %1
  %29 = bitcast i64* %2 to i8*, !dbg !930
  call void @llvm.lifetime.start.p0i8(i64 8, i8* nonnull %29) #7, !dbg !930
  %30 = tail call i64 inttoptr (i64 5 to i64 ()*)() #7, !dbg !939
  %31 = load i64, i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 1), align 8, !dbg !940, !tbaa !941
  %32 = sub i64 %30, %31, !dbg !942
  call void @llvm.dbg.value(metadata i64 %32, metadata !935, metadata !DIExpression()) #7, !dbg !943
  store i64 %32, i64* %2, align 8, !dbg !944, !tbaa !945
  %33 = bitcast i32* %3 to i8*, !dbg !946
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %33) #7, !dbg !946
  call void @llvm.dbg.value(metadata i32* %3, metadata !936, metadata !DIExpression(DW_OP_deref)) #7, !dbg !943
  %34 = call i64 inttoptr (i64 88 to i64 (i8*, i8*)*)(i8* bitcast (%struct.anon.7* @reclaimed_addrs to i8*), i8* nonnull %33) #7, !dbg !947
  %35 = icmp eq i64 %34, 0, !dbg !949
  br i1 %35, label %36, label %38, !dbg !950

36:                                               ; preds = %28
  %37 = load i32, i32* %3, align 4, !dbg !951, !tbaa !527
  call void @llvm.dbg.value(metadata i32 %37, metadata !936, metadata !DIExpression()) #7, !dbg !943
  br label %44, !dbg !952

38:                                               ; preds = %28
  call void @llvm.dbg.value(metadata i64* %2, metadata !935, metadata !DIExpression(DW_OP_deref)) #7, !dbg !943
  %39 = call i64 inttoptr (i64 164 to i64 (i8*, i8*, i8*, i64)*)(i8* bitcast (%struct.anon.4* @v6_state_map to i8*), i8* bitcast (i64 (%struct.bpf_map*, i8*, i8*, i8*)* @check_item to i8*), i8* nonnull %29, i64 0) #7, !dbg !953
  call void @llvm.dbg.value(metadata i32* %3, metadata !936, metadata !DIExpression(DW_OP_deref)) #7, !dbg !943
  %40 = call i64 inttoptr (i64 88 to i64 (i8*, i8*)*)(i8* bitcast (%struct.anon.7* @reclaimed_addrs to i8*), i8* nonnull %33) #7, !dbg !954
  %41 = icmp eq i64 %40, 0, !dbg !954
  %42 = load i32, i32* %3, align 4, !dbg !954
  call void @llvm.dbg.value(metadata i32 %42, metadata !936, metadata !DIExpression()) #7, !dbg !943
  %43 = select i1 %41, i32 %42, i32 0, !dbg !954
  br label %44, !dbg !955

44:                                               ; preds = %36, %38
  %45 = phi i32 [ %37, %36 ], [ %43, %38 ], !dbg !943
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %33) #7, !dbg !956
  call void @llvm.lifetime.end.p0i8(i64 8, i8* nonnull %29) #7, !dbg !956
  call void @llvm.dbg.value(metadata i32 %45, metadata !901, metadata !DIExpression()), !dbg !910
  store i32 %45, i32* %5, align 4, !dbg !957, !tbaa !527
  br label %54

46:                                               ; preds = %1
  %47 = and i64 %17, 4294967295, !dbg !958
  %48 = add i64 %17, 1, !dbg !960
  %49 = and i64 %48, 4294967295, !dbg !961
  %50 = cmpxchg i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 %47, i64 %49 seq_cst seq_cst, align 8, !dbg !962
  %51 = extractvalue { i64, i1 } %50, 1, !dbg !963
  call void @llvm.dbg.value(metadata i32 0, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  br i1 %51, label %52, label %22, !dbg !964

52:                                               ; preds = %169, %157, %145, %133, %121, %109, %97, %85, %73, %46
  %53 = phi i32 [ %20, %46 ], [ %26, %73 ], [ %83, %85 ], [ %95, %97 ], [ %107, %109 ], [ %119, %121 ], [ %131, %133 ], [ %143, %145 ], [ %155, %157 ], [ %167, %169 ], !dbg !926
  call void @llvm.dbg.value(metadata i32 %53, metadata !901, metadata !DIExpression()), !dbg !910
  store i32 %53, i32* %5, align 4, !dbg !965, !tbaa !527
  br label %54

54:                                               ; preds = %175, %44, %52
  %55 = phi i32 [ %176, %175 ], [ %45, %44 ], [ %53, %52 ], !dbg !967
  call void @llvm.dbg.value(metadata i32 %55, metadata !901, metadata !DIExpression()), !dbg !910
  %56 = icmp eq i32 %55, 0, !dbg !967
  br i1 %56, label %71, label %57, !dbg !969

57:                                               ; preds = %54
  store i32 %55, i32* %9, align 8, !dbg !970, !tbaa !803
  %58 = bitcast %struct.in6_addr* %0 to i8*, !dbg !971
  %59 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i8* bitcast (%struct.anon.4* @v6_state_map to i8*), i8* %58, i8* nonnull %6, i64 1) #7, !dbg !973
  %60 = icmp eq i64 %59, 0, !dbg !973
  br i1 %60, label %61, label %69, !dbg !974

61:                                               ; preds = %57
  call void @llvm.dbg.value(metadata i32* %5, metadata !901, metadata !DIExpression(DW_OP_deref)), !dbg !910
  %62 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i8* bitcast (%struct.anon.5* @v4_reversemap to i8*), i8* nonnull %16, i8* %58, i64 1) #7, !dbg !975
  %63 = icmp eq i64 %62, 0, !dbg !975
  br i1 %63, label %64, label %67, !dbg !977

64:                                               ; preds = %61
  %65 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.anon.4* @v6_state_map to i8*), i8* %58) #7, !dbg !978
  %66 = bitcast i8* %65 to %struct.v6_addr_state*, !dbg !978
  br label %71, !dbg !979

67:                                               ; preds = %61
  call void @llvm.dbg.label(metadata !908), !dbg !980
  %68 = call i64 inttoptr (i64 3 to i64 (i8*, i8*)*)(i8* bitcast (%struct.anon.4* @v6_state_map to i8*), i8* %58) #7, !dbg !981
  br label %69, !dbg !981

69:                                               ; preds = %57, %67
  call void @llvm.dbg.label(metadata !909), !dbg !982
  call void @llvm.dbg.value(metadata i32* %5, metadata !901, metadata !DIExpression(DW_OP_deref)), !dbg !910
  %70 = call i64 inttoptr (i64 87 to i64 (i8*, i8*, i64)*)(i8* bitcast (%struct.anon.7* @reclaimed_addrs to i8*), i8* nonnull %16, i64 0) #7, !dbg !983
  br label %71, !dbg !984

71:                                               ; preds = %54, %69, %64
  %72 = phi %struct.v6_addr_state* [ null, %69 ], [ %66, %64 ], [ null, %54 ], !dbg !910
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %16) #7, !dbg !985
  call void @llvm.lifetime.end.p0i8(i64 16, i8* nonnull %6) #7, !dbg !985
  ret %struct.v6_addr_state* %72, !dbg !985

73:                                               ; preds = %22
  %74 = and i64 %23, 4294967295, !dbg !958
  %75 = add i64 %23, 1, !dbg !960
  %76 = and i64 %75, 4294967295, !dbg !961
  %77 = cmpxchg i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 %74, i64 %76 seq_cst seq_cst, align 8, !dbg !962
  %78 = extractvalue { i64, i1 } %77, 1, !dbg !963
  call void @llvm.dbg.value(metadata i32 1, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  br i1 %78, label %52, label %79, !dbg !964

79:                                               ; preds = %73
  call void @llvm.dbg.value(metadata i32 2, metadata !902, metadata !DIExpression()), !dbg !910
  call void @llvm.dbg.value(metadata i32 1, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  call void @llvm.dbg.value(metadata i32 2, metadata !902, metadata !DIExpression()), !dbg !910
  %80 = atomicrmw or i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 0 seq_cst, align 8, !dbg !923
  %81 = trunc i64 %80 to i32, !dbg !923
  call void @llvm.dbg.value(metadata i32 %81, metadata !907, metadata !DIExpression()), !dbg !924
  %82 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 3), align 8, !dbg !925, !tbaa !535
  %83 = add i32 %82, %81, !dbg !926
  call void @llvm.dbg.value(metadata i32 %83, metadata !903, metadata !DIExpression()), !dbg !924
  %84 = icmp ult i32 %83, %15, !dbg !927
  br i1 %84, label %85, label %28, !dbg !929

85:                                               ; preds = %79
  %86 = and i64 %80, 4294967295, !dbg !958
  %87 = add i64 %80, 1, !dbg !960
  %88 = and i64 %87, 4294967295, !dbg !961
  %89 = cmpxchg i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 %86, i64 %88 seq_cst seq_cst, align 8, !dbg !962
  %90 = extractvalue { i64, i1 } %89, 1, !dbg !963
  call void @llvm.dbg.value(metadata i32 2, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  br i1 %90, label %52, label %91, !dbg !964

91:                                               ; preds = %85
  call void @llvm.dbg.value(metadata i32 3, metadata !902, metadata !DIExpression()), !dbg !910
  call void @llvm.dbg.value(metadata i32 2, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  call void @llvm.dbg.value(metadata i32 3, metadata !902, metadata !DIExpression()), !dbg !910
  %92 = atomicrmw or i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 0 seq_cst, align 8, !dbg !923
  %93 = trunc i64 %92 to i32, !dbg !923
  call void @llvm.dbg.value(metadata i32 %93, metadata !907, metadata !DIExpression()), !dbg !924
  %94 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 3), align 8, !dbg !925, !tbaa !535
  %95 = add i32 %94, %93, !dbg !926
  call void @llvm.dbg.value(metadata i32 %95, metadata !903, metadata !DIExpression()), !dbg !924
  %96 = icmp ult i32 %95, %15, !dbg !927
  br i1 %96, label %97, label %28, !dbg !929

97:                                               ; preds = %91
  %98 = and i64 %92, 4294967295, !dbg !958
  %99 = add i64 %92, 1, !dbg !960
  %100 = and i64 %99, 4294967295, !dbg !961
  %101 = cmpxchg i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 %98, i64 %100 seq_cst seq_cst, align 8, !dbg !962
  %102 = extractvalue { i64, i1 } %101, 1, !dbg !963
  call void @llvm.dbg.value(metadata i32 3, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  br i1 %102, label %52, label %103, !dbg !964

103:                                              ; preds = %97
  call void @llvm.dbg.value(metadata i32 4, metadata !902, metadata !DIExpression()), !dbg !910
  call void @llvm.dbg.value(metadata i32 3, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  call void @llvm.dbg.value(metadata i32 4, metadata !902, metadata !DIExpression()), !dbg !910
  %104 = atomicrmw or i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 0 seq_cst, align 8, !dbg !923
  %105 = trunc i64 %104 to i32, !dbg !923
  call void @llvm.dbg.value(metadata i32 %105, metadata !907, metadata !DIExpression()), !dbg !924
  %106 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 3), align 8, !dbg !925, !tbaa !535
  %107 = add i32 %106, %105, !dbg !926
  call void @llvm.dbg.value(metadata i32 %107, metadata !903, metadata !DIExpression()), !dbg !924
  %108 = icmp ult i32 %107, %15, !dbg !927
  br i1 %108, label %109, label %28, !dbg !929

109:                                              ; preds = %103
  %110 = and i64 %104, 4294967295, !dbg !958
  %111 = add i64 %104, 1, !dbg !960
  %112 = and i64 %111, 4294967295, !dbg !961
  %113 = cmpxchg i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 %110, i64 %112 seq_cst seq_cst, align 8, !dbg !962
  %114 = extractvalue { i64, i1 } %113, 1, !dbg !963
  call void @llvm.dbg.value(metadata i32 4, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  br i1 %114, label %52, label %115, !dbg !964

115:                                              ; preds = %109
  call void @llvm.dbg.value(metadata i32 5, metadata !902, metadata !DIExpression()), !dbg !910
  call void @llvm.dbg.value(metadata i32 4, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  call void @llvm.dbg.value(metadata i32 5, metadata !902, metadata !DIExpression()), !dbg !910
  %116 = atomicrmw or i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 0 seq_cst, align 8, !dbg !923
  %117 = trunc i64 %116 to i32, !dbg !923
  call void @llvm.dbg.value(metadata i32 %117, metadata !907, metadata !DIExpression()), !dbg !924
  %118 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 3), align 8, !dbg !925, !tbaa !535
  %119 = add i32 %118, %117, !dbg !926
  call void @llvm.dbg.value(metadata i32 %119, metadata !903, metadata !DIExpression()), !dbg !924
  %120 = icmp ult i32 %119, %15, !dbg !927
  br i1 %120, label %121, label %28, !dbg !929

121:                                              ; preds = %115
  %122 = and i64 %116, 4294967295, !dbg !958
  %123 = add i64 %116, 1, !dbg !960
  %124 = and i64 %123, 4294967295, !dbg !961
  %125 = cmpxchg i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 %122, i64 %124 seq_cst seq_cst, align 8, !dbg !962
  %126 = extractvalue { i64, i1 } %125, 1, !dbg !963
  call void @llvm.dbg.value(metadata i32 5, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  br i1 %126, label %52, label %127, !dbg !964

127:                                              ; preds = %121
  call void @llvm.dbg.value(metadata i32 6, metadata !902, metadata !DIExpression()), !dbg !910
  call void @llvm.dbg.value(metadata i32 5, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  call void @llvm.dbg.value(metadata i32 6, metadata !902, metadata !DIExpression()), !dbg !910
  %128 = atomicrmw or i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 0 seq_cst, align 8, !dbg !923
  %129 = trunc i64 %128 to i32, !dbg !923
  call void @llvm.dbg.value(metadata i32 %129, metadata !907, metadata !DIExpression()), !dbg !924
  %130 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 3), align 8, !dbg !925, !tbaa !535
  %131 = add i32 %130, %129, !dbg !926
  call void @llvm.dbg.value(metadata i32 %131, metadata !903, metadata !DIExpression()), !dbg !924
  %132 = icmp ult i32 %131, %15, !dbg !927
  br i1 %132, label %133, label %28, !dbg !929

133:                                              ; preds = %127
  %134 = and i64 %128, 4294967295, !dbg !958
  %135 = add i64 %128, 1, !dbg !960
  %136 = and i64 %135, 4294967295, !dbg !961
  %137 = cmpxchg i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 %134, i64 %136 seq_cst seq_cst, align 8, !dbg !962
  %138 = extractvalue { i64, i1 } %137, 1, !dbg !963
  call void @llvm.dbg.value(metadata i32 6, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  br i1 %138, label %52, label %139, !dbg !964

139:                                              ; preds = %133
  call void @llvm.dbg.value(metadata i32 7, metadata !902, metadata !DIExpression()), !dbg !910
  call void @llvm.dbg.value(metadata i32 6, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  call void @llvm.dbg.value(metadata i32 7, metadata !902, metadata !DIExpression()), !dbg !910
  %140 = atomicrmw or i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 0 seq_cst, align 8, !dbg !923
  %141 = trunc i64 %140 to i32, !dbg !923
  call void @llvm.dbg.value(metadata i32 %141, metadata !907, metadata !DIExpression()), !dbg !924
  %142 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 3), align 8, !dbg !925, !tbaa !535
  %143 = add i32 %142, %141, !dbg !926
  call void @llvm.dbg.value(metadata i32 %143, metadata !903, metadata !DIExpression()), !dbg !924
  %144 = icmp ult i32 %143, %15, !dbg !927
  br i1 %144, label %145, label %28, !dbg !929

145:                                              ; preds = %139
  %146 = and i64 %140, 4294967295, !dbg !958
  %147 = add i64 %140, 1, !dbg !960
  %148 = and i64 %147, 4294967295, !dbg !961
  %149 = cmpxchg i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 %146, i64 %148 seq_cst seq_cst, align 8, !dbg !962
  %150 = extractvalue { i64, i1 } %149, 1, !dbg !963
  call void @llvm.dbg.value(metadata i32 7, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  br i1 %150, label %52, label %151, !dbg !964

151:                                              ; preds = %145
  call void @llvm.dbg.value(metadata i32 8, metadata !902, metadata !DIExpression()), !dbg !910
  call void @llvm.dbg.value(metadata i32 7, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  call void @llvm.dbg.value(metadata i32 8, metadata !902, metadata !DIExpression()), !dbg !910
  %152 = atomicrmw or i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 0 seq_cst, align 8, !dbg !923
  %153 = trunc i64 %152 to i32, !dbg !923
  call void @llvm.dbg.value(metadata i32 %153, metadata !907, metadata !DIExpression()), !dbg !924
  %154 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 3), align 8, !dbg !925, !tbaa !535
  %155 = add i32 %154, %153, !dbg !926
  call void @llvm.dbg.value(metadata i32 %155, metadata !903, metadata !DIExpression()), !dbg !924
  %156 = icmp ult i32 %155, %15, !dbg !927
  br i1 %156, label %157, label %28, !dbg !929

157:                                              ; preds = %151
  %158 = and i64 %152, 4294967295, !dbg !958
  %159 = add i64 %152, 1, !dbg !960
  %160 = and i64 %159, 4294967295, !dbg !961
  %161 = cmpxchg i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 %158, i64 %160 seq_cst seq_cst, align 8, !dbg !962
  %162 = extractvalue { i64, i1 } %161, 1, !dbg !963
  call void @llvm.dbg.value(metadata i32 8, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  br i1 %162, label %52, label %163, !dbg !964

163:                                              ; preds = %157
  call void @llvm.dbg.value(metadata i32 9, metadata !902, metadata !DIExpression()), !dbg !910
  call void @llvm.dbg.value(metadata i32 8, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  call void @llvm.dbg.value(metadata i32 9, metadata !902, metadata !DIExpression()), !dbg !910
  %164 = atomicrmw or i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 0 seq_cst, align 8, !dbg !923
  %165 = trunc i64 %164 to i32, !dbg !923
  call void @llvm.dbg.value(metadata i32 %165, metadata !907, metadata !DIExpression()), !dbg !924
  %166 = load i32, i32* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 3), align 8, !dbg !925, !tbaa !535
  %167 = add i32 %166, %165, !dbg !926
  call void @llvm.dbg.value(metadata i32 %167, metadata !903, metadata !DIExpression()), !dbg !924
  %168 = icmp ult i32 %167, %15, !dbg !927
  br i1 %168, label %169, label %28, !dbg !929

169:                                              ; preds = %163
  %170 = and i64 %164, 4294967295, !dbg !958
  %171 = add i64 %164, 1, !dbg !960
  %172 = and i64 %171, 4294967295, !dbg !961
  %173 = cmpxchg i64* getelementptr inbounds (%struct.nat64_config, %struct.nat64_config* @config, i64 0, i32 2), i64 %170, i64 %172 seq_cst seq_cst, align 8, !dbg !962
  %174 = extractvalue { i64, i1 } %173, 1, !dbg !963
  call void @llvm.dbg.value(metadata i32 9, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  br i1 %174, label %52, label %175, !dbg !964

175:                                              ; preds = %169
  call void @llvm.dbg.value(metadata i32 10, metadata !902, metadata !DIExpression()), !dbg !910
  call void @llvm.dbg.value(metadata i32 9, metadata !902, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !910
  %176 = load i32, i32* %5, align 4, !dbg !967, !tbaa !527
  br label %54, !dbg !967
}

; Function Attrs: nounwind
define internal i64 @check_item(%struct.bpf_map* %0, i8* %1, i8* nocapture readonly %2, i8* nocapture readonly %3) #0 !dbg !986 {
  %5 = alloca i32, align 4
  call void @llvm.dbg.value(metadata %struct.bpf_map* %0, metadata !992, metadata !DIExpression()), !dbg !1001
  call void @llvm.dbg.value(metadata i8* %1, metadata !993, metadata !DIExpression()), !dbg !1001
  call void @llvm.dbg.value(metadata i8* %2, metadata !994, metadata !DIExpression()), !dbg !1001
  call void @llvm.dbg.value(metadata i8* %3, metadata !995, metadata !DIExpression()), !dbg !1001
  call void @llvm.dbg.value(metadata i8* %2, metadata !996, metadata !DIExpression()), !dbg !1001
  %6 = bitcast i8* %3 to i64*, !dbg !1002
  %7 = load i64, i64* %6, align 8, !dbg !1003, !tbaa !945
  call void @llvm.dbg.value(metadata i64 %7, metadata !997, metadata !DIExpression()), !dbg !1001
  %8 = bitcast i8* %2 to i64*, !dbg !1004
  %9 = load i64, i64* %8, align 8, !dbg !1004, !tbaa !812
  %10 = icmp ult i64 %9, %7, !dbg !1005
  br i1 %10, label %11, label %25, !dbg !1006

11:                                               ; preds = %4
  %12 = getelementptr inbounds i8, i8* %2, i64 12, !dbg !1007
  %13 = bitcast i8* %12 to i32*, !dbg !1007
  %14 = load i32, i32* %13, align 4, !dbg !1007, !tbaa !915
  %15 = icmp eq i32 %14, 0, !dbg !1008
  br i1 %15, label %16, label %25, !dbg !1009

16:                                               ; preds = %11
  %17 = bitcast i32* %5 to i8*, !dbg !1010
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %17) #7, !dbg !1010
  %18 = getelementptr inbounds i8, i8* %2, i64 8, !dbg !1011
  %19 = bitcast i8* %18 to i32*, !dbg !1011
  %20 = load i32, i32* %19, align 8, !dbg !1011, !tbaa !803
  call void @llvm.dbg.value(metadata i32 %20, metadata !998, metadata !DIExpression()), !dbg !1012
  store i32 %20, i32* %5, align 4, !dbg !1013, !tbaa !527
  %21 = bitcast %struct.bpf_map* %0 to i8*, !dbg !1014
  %22 = tail call i64 inttoptr (i64 3 to i64 (i8*, i8*)*)(i8* %21, i8* %1) #7, !dbg !1015
  call void @llvm.dbg.value(metadata i32* %5, metadata !998, metadata !DIExpression(DW_OP_deref)), !dbg !1012
  %23 = call i64 inttoptr (i64 3 to i64 (i8*, i8*)*)(i8* bitcast (%struct.anon.5* @v4_reversemap to i8*), i8* nonnull %17) #7, !dbg !1016
  %24 = call i64 inttoptr (i64 87 to i64 (i8*, i8*, i64)*)(i8* bitcast (%struct.anon.7* @reclaimed_addrs to i8*), i8* nonnull %17, i64 0) #7, !dbg !1017
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %17) #7, !dbg !1018
  br label %25

25:                                               ; preds = %4, %11, %16
  %26 = phi i64 [ 1, %16 ], [ 0, %11 ], [ 0, %4 ], !dbg !1001
  ret i64 %26, !dbg !1019
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #5

; Function Attrs: nounwind readnone
declare i1 @llvm.bpf.passthrough.i1.i1(i32, i1) #6

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare i8 @llvm.fshl.i8(i8, i8, i8) #5

attributes #0 = { nounwind "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #1 = { mustprogress nofree nosync nounwind readnone speculatable willreturn }
attributes #2 = { argmemonly mustprogress nofree nosync nounwind willreturn }
attributes #3 = { argmemonly mustprogress nofree nounwind willreturn writeonly }
attributes #4 = { argmemonly mustprogress nofree nounwind willreturn }
attributes #5 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #6 = { nounwind readnone }
attributes #7 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!296, !297, !298, !299}
!llvm.ident = !{!300}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 13, type: !295, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "Ubuntu clang version 13.0.0-2", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, retainedTypes: !16, globals: !30, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "nat64_kern.c", directory: "/home/sha68/bpf-examples/nat64-bpf")
!4 = !{!5, !13}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, file: !6, line: 397, baseType: !7, size: 32, elements: !8)
!6 = !DIFile(filename: "../lib/../headers/linux/bpf.h", directory: "/home/sha68/bpf-examples/nat64-bpf")
!7 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!8 = !{!9, !10, !11, !12}
!9 = !DIEnumerator(name: "BPF_ANY", value: 0)
!10 = !DIEnumerator(name: "BPF_NOEXIST", value: 1)
!11 = !DIEnumerator(name: "BPF_EXIST", value: 2)
!12 = !DIEnumerator(name: "BPF_F_LOCK", value: 4)
!13 = !DICompositeType(tag: DW_TAG_enumeration_type, file: !6, line: 4033, baseType: !7, size: 32, elements: !14)
!14 = !{!15}
!15 = !DIEnumerator(name: "BPF_F_INGRESS", value: 1)
!16 = !{!17, !18, !19, !22, !23, !26, !28}
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!18 = !DIBasicType(name: "long long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!19 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u16", file: !20, line: 24, baseType: !21)
!20 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "")
!21 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!22 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !20, line: 27, baseType: !7)
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 64)
!24 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be32", file: !25, line: 27, baseType: !22)
!25 = !DIFile(filename: "/usr/include/linux/types.h", directory: "")
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!27 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!28 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!29 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u64", file: !20, line: 31, baseType: !18)
!30 = !{!0, !31, !62, !83, !93, !110, !126, !135, !142, !238, !252, !257, !262, !267, !272, !277, !282, !290}
!31 = !DIGlobalVariableExpression(var: !32, expr: !DIExpression())
!32 = distinct !DIGlobalVariable(name: "config", scope: !2, file: !3, line: 15, type: !33, isLocal: false, isDefinition: true)
!33 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "nat64_config", file: !34, line: 6, size: 320, elements: !35)
!34 = !DIFile(filename: "./nat64.h", directory: "/home/sha68/bpf-examples/nat64-bpf")
!35 = !{!36, !58, !59, !60, !61}
!36 = !DIDerivedType(tag: DW_TAG_member, name: "v6_prefix", scope: !33, file: !34, line: 7, baseType: !37, size: 128)
!37 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "in6_addr", file: !38, line: 33, size: 128, elements: !39)
!38 = !DIFile(filename: "/usr/include/linux/in6.h", directory: "")
!39 = !{!40}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "in6_u", scope: !37, file: !38, line: 40, baseType: !41, size: 128)
!41 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !37, file: !38, line: 34, size: 128, elements: !42)
!42 = !{!43, !49, !54}
!43 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr8", scope: !41, file: !38, line: 35, baseType: !44, size: 128)
!44 = !DICompositeType(tag: DW_TAG_array_type, baseType: !45, size: 128, elements: !47)
!45 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u8", file: !20, line: 21, baseType: !46)
!46 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!47 = !{!48}
!48 = !DISubrange(count: 16)
!49 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr16", scope: !41, file: !38, line: 37, baseType: !50, size: 128)
!50 = !DICompositeType(tag: DW_TAG_array_type, baseType: !51, size: 128, elements: !52)
!51 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be16", file: !25, line: 25, baseType: !19)
!52 = !{!53}
!53 = !DISubrange(count: 8)
!54 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr32", scope: !41, file: !38, line: 38, baseType: !55, size: 128)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !24, size: 128, elements: !56)
!56 = !{!57}
!57 = !DISubrange(count: 4)
!58 = !DIDerivedType(tag: DW_TAG_member, name: "timeout_ns", scope: !33, file: !34, line: 8, baseType: !29, size: 64, offset: 128)
!59 = !DIDerivedType(tag: DW_TAG_member, name: "next_addr", scope: !33, file: !34, line: 9, baseType: !29, size: 64, offset: 192)
!60 = !DIDerivedType(tag: DW_TAG_member, name: "v4_prefix", scope: !33, file: !34, line: 10, baseType: !22, size: 32, offset: 256)
!61 = !DIDerivedType(tag: DW_TAG_member, name: "v4_mask", scope: !33, file: !34, line: 11, baseType: !22, size: 32, offset: 288)
!62 = !DIGlobalVariableExpression(var: !63, expr: !DIExpression())
!63 = distinct !DIGlobalVariable(name: "v6_state_map", scope: !2, file: !3, line: 23, type: !64, isLocal: false, isDefinition: true)
!64 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 17, size: 320, elements: !65)
!65 = !{!66, !72, !74, !81, !82}
!66 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !64, file: !3, line: 18, baseType: !67, size: 64)
!67 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !68, size: 64)
!68 = !DICompositeType(tag: DW_TAG_array_type, baseType: !69, size: 32, elements: !70)
!69 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!70 = !{!71}
!71 = !DISubrange(count: 1)
!72 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !64, file: !3, line: 19, baseType: !73, size: 64, offset: 64)
!73 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !37, size: 64)
!74 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !64, file: !3, line: 20, baseType: !75, size: 64, offset: 128)
!75 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !76, size: 64)
!76 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "v6_addr_state", file: !34, line: 14, size: 128, elements: !77)
!77 = !{!78, !79, !80}
!78 = !DIDerivedType(tag: DW_TAG_member, name: "last_seen", scope: !76, file: !34, line: 15, baseType: !29, size: 64)
!79 = !DIDerivedType(tag: DW_TAG_member, name: "v4_addr", scope: !76, file: !34, line: 16, baseType: !22, size: 32, offset: 64)
!80 = !DIDerivedType(tag: DW_TAG_member, name: "static_conf", scope: !76, file: !34, line: 17, baseType: !22, size: 32, offset: 96)
!81 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !64, file: !3, line: 21, baseType: !67, size: 64, offset: 192)
!82 = !DIDerivedType(tag: DW_TAG_member, name: "map_flags", scope: !64, file: !3, line: 22, baseType: !67, size: 64, offset: 256)
!83 = !DIGlobalVariableExpression(var: !84, expr: !DIExpression())
!84 = distinct !DIGlobalVariable(name: "v4_reversemap", scope: !2, file: !3, line: 31, type: !85, isLocal: false, isDefinition: true)
!85 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 25, size: 320, elements: !86)
!86 = !{!87, !88, !90, !91, !92}
!87 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !85, file: !3, line: 26, baseType: !67, size: 64)
!88 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !85, file: !3, line: 27, baseType: !89, size: 64, offset: 64)
!89 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!90 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !85, file: !3, line: 28, baseType: !73, size: 64, offset: 128)
!91 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !85, file: !3, line: 29, baseType: !67, size: 64, offset: 192)
!92 = !DIDerivedType(tag: DW_TAG_member, name: "map_flags", scope: !85, file: !3, line: 30, baseType: !67, size: 64, offset: 256)
!93 = !DIGlobalVariableExpression(var: !94, expr: !DIExpression())
!94 = distinct !DIGlobalVariable(name: "allowed_v6_src", scope: !2, file: !3, line: 39, type: !95, isLocal: false, isDefinition: true)
!95 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 33, size: 320, elements: !96)
!96 = !{!97, !102, !105, !108, !109}
!97 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !95, file: !3, line: 34, baseType: !98, size: 64)
!98 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !99, size: 64)
!99 = !DICompositeType(tag: DW_TAG_array_type, baseType: !69, size: 352, elements: !100)
!100 = !{!101}
!101 = !DISubrange(count: 11)
!102 = !DIDerivedType(tag: DW_TAG_member, name: "key_size", scope: !95, file: !3, line: 35, baseType: !103, size: 64, offset: 64)
!103 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !104, size: 64)
!104 = !DICompositeType(tag: DW_TAG_array_type, baseType: !69, size: 512, elements: !47)
!105 = !DIDerivedType(tag: DW_TAG_member, name: "value_size", scope: !95, file: !3, line: 36, baseType: !106, size: 64, offset: 128)
!106 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !107, size: 64)
!107 = !DICompositeType(tag: DW_TAG_array_type, baseType: !69, size: 128, elements: !56)
!108 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !95, file: !3, line: 37, baseType: !67, size: 64, offset: 192)
!109 = !DIDerivedType(tag: DW_TAG_member, name: "map_flags", scope: !95, file: !3, line: 38, baseType: !67, size: 64, offset: 256)
!110 = !DIGlobalVariableExpression(var: !111, expr: !DIExpression())
!111 = distinct !DIGlobalVariable(name: "reclaimed_addrs", scope: !2, file: !3, line: 46, type: !112, isLocal: false, isDefinition: true)
!112 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 41, size: 256, elements: !113)
!113 = !{!114, !119, !124, !125}
!114 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !112, file: !3, line: 42, baseType: !115, size: 64)
!115 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !116, size: 64)
!116 = !DICompositeType(tag: DW_TAG_array_type, baseType: !69, size: 704, elements: !117)
!117 = !{!118}
!118 = !DISubrange(count: 22)
!119 = !DIDerivedType(tag: DW_TAG_member, name: "key_size", scope: !112, file: !3, line: 43, baseType: !120, size: 64, offset: 64)
!120 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !121, size: 64)
!121 = !DICompositeType(tag: DW_TAG_array_type, baseType: !69, elements: !122)
!122 = !{!123}
!123 = !DISubrange(count: 0)
!124 = !DIDerivedType(tag: DW_TAG_member, name: "value_size", scope: !112, file: !3, line: 44, baseType: !106, size: 64, offset: 128)
!125 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !112, file: !3, line: 45, baseType: !67, size: 64, offset: 192)
!126 = !DIGlobalVariableExpression(var: !127, expr: !DIExpression())
!127 = distinct !DIGlobalVariable(name: "bpf_trace_printk", scope: !2, file: !128, line: 171, type: !129, isLocal: true, isDefinition: true)
!128 = !DIFile(filename: "../lib/libbpf-install/usr/include/bpf/bpf_helper_defs.h", directory: "/home/sha68/bpf-examples/nat64-bpf")
!129 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !130, size: 64)
!130 = !DISubroutineType(types: !131)
!131 = !{!132, !133, !22, null}
!132 = !DIBasicType(name: "long int", size: 64, encoding: DW_ATE_signed)
!133 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !134, size: 64)
!134 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !27)
!135 = !DIGlobalVariableExpression(var: !136, expr: !DIExpression())
!136 = distinct !DIGlobalVariable(name: "bpf_map_lookup_elem", scope: !2, file: !128, line: 50, type: !137, isLocal: true, isDefinition: true)
!137 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !138, size: 64)
!138 = !DISubroutineType(types: !139)
!139 = !{!17, !17, !140}
!140 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !141, size: 64)
!141 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!142 = !DIGlobalVariableExpression(var: !143, expr: !DIExpression())
!143 = distinct !DIGlobalVariable(name: "bpf_skb_change_proto", scope: !2, file: !128, line: 850, type: !144, isLocal: true, isDefinition: true)
!144 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !145, size: 64)
!145 = !DISubroutineType(types: !146)
!146 = !{!132, !147, !51, !29}
!147 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !148, size: 64)
!148 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "__sk_buff", file: !6, line: 4183, size: 1472, elements: !149)
!149 = !{!150, !151, !152, !153, !154, !155, !156, !157, !158, !159, !160, !161, !162, !166, !167, !168, !169, !170, !171, !172, !173, !174, !176, !177, !178, !179, !180, !212, !213, !214, !215, !237}
!150 = !DIDerivedType(tag: DW_TAG_member, name: "len", scope: !148, file: !6, line: 4184, baseType: !22, size: 32)
!151 = !DIDerivedType(tag: DW_TAG_member, name: "pkt_type", scope: !148, file: !6, line: 4185, baseType: !22, size: 32, offset: 32)
!152 = !DIDerivedType(tag: DW_TAG_member, name: "mark", scope: !148, file: !6, line: 4186, baseType: !22, size: 32, offset: 64)
!153 = !DIDerivedType(tag: DW_TAG_member, name: "queue_mapping", scope: !148, file: !6, line: 4187, baseType: !22, size: 32, offset: 96)
!154 = !DIDerivedType(tag: DW_TAG_member, name: "protocol", scope: !148, file: !6, line: 4188, baseType: !22, size: 32, offset: 128)
!155 = !DIDerivedType(tag: DW_TAG_member, name: "vlan_present", scope: !148, file: !6, line: 4189, baseType: !22, size: 32, offset: 160)
!156 = !DIDerivedType(tag: DW_TAG_member, name: "vlan_tci", scope: !148, file: !6, line: 4190, baseType: !22, size: 32, offset: 192)
!157 = !DIDerivedType(tag: DW_TAG_member, name: "vlan_proto", scope: !148, file: !6, line: 4191, baseType: !22, size: 32, offset: 224)
!158 = !DIDerivedType(tag: DW_TAG_member, name: "priority", scope: !148, file: !6, line: 4192, baseType: !22, size: 32, offset: 256)
!159 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !148, file: !6, line: 4193, baseType: !22, size: 32, offset: 288)
!160 = !DIDerivedType(tag: DW_TAG_member, name: "ifindex", scope: !148, file: !6, line: 4194, baseType: !22, size: 32, offset: 320)
!161 = !DIDerivedType(tag: DW_TAG_member, name: "tc_index", scope: !148, file: !6, line: 4195, baseType: !22, size: 32, offset: 352)
!162 = !DIDerivedType(tag: DW_TAG_member, name: "cb", scope: !148, file: !6, line: 4196, baseType: !163, size: 160, offset: 384)
!163 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 160, elements: !164)
!164 = !{!165}
!165 = !DISubrange(count: 5)
!166 = !DIDerivedType(tag: DW_TAG_member, name: "hash", scope: !148, file: !6, line: 4197, baseType: !22, size: 32, offset: 544)
!167 = !DIDerivedType(tag: DW_TAG_member, name: "tc_classid", scope: !148, file: !6, line: 4198, baseType: !22, size: 32, offset: 576)
!168 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !148, file: !6, line: 4199, baseType: !22, size: 32, offset: 608)
!169 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !148, file: !6, line: 4200, baseType: !22, size: 32, offset: 640)
!170 = !DIDerivedType(tag: DW_TAG_member, name: "napi_id", scope: !148, file: !6, line: 4201, baseType: !22, size: 32, offset: 672)
!171 = !DIDerivedType(tag: DW_TAG_member, name: "family", scope: !148, file: !6, line: 4204, baseType: !22, size: 32, offset: 704)
!172 = !DIDerivedType(tag: DW_TAG_member, name: "remote_ip4", scope: !148, file: !6, line: 4205, baseType: !22, size: 32, offset: 736)
!173 = !DIDerivedType(tag: DW_TAG_member, name: "local_ip4", scope: !148, file: !6, line: 4206, baseType: !22, size: 32, offset: 768)
!174 = !DIDerivedType(tag: DW_TAG_member, name: "remote_ip6", scope: !148, file: !6, line: 4207, baseType: !175, size: 128, offset: 800)
!175 = !DICompositeType(tag: DW_TAG_array_type, baseType: !22, size: 128, elements: !56)
!176 = !DIDerivedType(tag: DW_TAG_member, name: "local_ip6", scope: !148, file: !6, line: 4208, baseType: !175, size: 128, offset: 928)
!177 = !DIDerivedType(tag: DW_TAG_member, name: "remote_port", scope: !148, file: !6, line: 4209, baseType: !22, size: 32, offset: 1056)
!178 = !DIDerivedType(tag: DW_TAG_member, name: "local_port", scope: !148, file: !6, line: 4210, baseType: !22, size: 32, offset: 1088)
!179 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !148, file: !6, line: 4213, baseType: !22, size: 32, offset: 1120)
!180 = !DIDerivedType(tag: DW_TAG_member, scope: !148, file: !6, line: 4214, baseType: !181, size: 64, align: 64, offset: 1152)
!181 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !148, file: !6, line: 4214, size: 64, align: 64, elements: !182)
!182 = !{!183}
!183 = !DIDerivedType(tag: DW_TAG_member, name: "flow_keys", scope: !181, file: !6, line: 4214, baseType: !184, size: 64)
!184 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !185, size: 64)
!185 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_flow_keys", file: !6, line: 5041, size: 448, elements: !186)
!186 = !{!187, !188, !189, !190, !191, !192, !193, !194, !195, !196, !197, !210, !211}
!187 = !DIDerivedType(tag: DW_TAG_member, name: "nhoff", scope: !185, file: !6, line: 5042, baseType: !19, size: 16)
!188 = !DIDerivedType(tag: DW_TAG_member, name: "thoff", scope: !185, file: !6, line: 5043, baseType: !19, size: 16, offset: 16)
!189 = !DIDerivedType(tag: DW_TAG_member, name: "addr_proto", scope: !185, file: !6, line: 5044, baseType: !19, size: 16, offset: 32)
!190 = !DIDerivedType(tag: DW_TAG_member, name: "is_frag", scope: !185, file: !6, line: 5045, baseType: !45, size: 8, offset: 48)
!191 = !DIDerivedType(tag: DW_TAG_member, name: "is_first_frag", scope: !185, file: !6, line: 5046, baseType: !45, size: 8, offset: 56)
!192 = !DIDerivedType(tag: DW_TAG_member, name: "is_encap", scope: !185, file: !6, line: 5047, baseType: !45, size: 8, offset: 64)
!193 = !DIDerivedType(tag: DW_TAG_member, name: "ip_proto", scope: !185, file: !6, line: 5048, baseType: !45, size: 8, offset: 72)
!194 = !DIDerivedType(tag: DW_TAG_member, name: "n_proto", scope: !185, file: !6, line: 5049, baseType: !51, size: 16, offset: 80)
!195 = !DIDerivedType(tag: DW_TAG_member, name: "sport", scope: !185, file: !6, line: 5050, baseType: !51, size: 16, offset: 96)
!196 = !DIDerivedType(tag: DW_TAG_member, name: "dport", scope: !185, file: !6, line: 5051, baseType: !51, size: 16, offset: 112)
!197 = !DIDerivedType(tag: DW_TAG_member, scope: !185, file: !6, line: 5052, baseType: !198, size: 256, offset: 128)
!198 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !185, file: !6, line: 5052, size: 256, elements: !199)
!199 = !{!200, !205}
!200 = !DIDerivedType(tag: DW_TAG_member, scope: !198, file: !6, line: 5053, baseType: !201, size: 64)
!201 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !198, file: !6, line: 5053, size: 64, elements: !202)
!202 = !{!203, !204}
!203 = !DIDerivedType(tag: DW_TAG_member, name: "ipv4_src", scope: !201, file: !6, line: 5054, baseType: !24, size: 32)
!204 = !DIDerivedType(tag: DW_TAG_member, name: "ipv4_dst", scope: !201, file: !6, line: 5055, baseType: !24, size: 32, offset: 32)
!205 = !DIDerivedType(tag: DW_TAG_member, scope: !198, file: !6, line: 5057, baseType: !206, size: 256)
!206 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !198, file: !6, line: 5057, size: 256, elements: !207)
!207 = !{!208, !209}
!208 = !DIDerivedType(tag: DW_TAG_member, name: "ipv6_src", scope: !206, file: !6, line: 5058, baseType: !175, size: 128)
!209 = !DIDerivedType(tag: DW_TAG_member, name: "ipv6_dst", scope: !206, file: !6, line: 5059, baseType: !175, size: 128, offset: 128)
!210 = !DIDerivedType(tag: DW_TAG_member, name: "flags", scope: !185, file: !6, line: 5062, baseType: !22, size: 32, offset: 384)
!211 = !DIDerivedType(tag: DW_TAG_member, name: "flow_label", scope: !185, file: !6, line: 5063, baseType: !24, size: 32, offset: 416)
!212 = !DIDerivedType(tag: DW_TAG_member, name: "tstamp", scope: !148, file: !6, line: 4215, baseType: !29, size: 64, offset: 1216)
!213 = !DIDerivedType(tag: DW_TAG_member, name: "wire_len", scope: !148, file: !6, line: 4216, baseType: !22, size: 32, offset: 1280)
!214 = !DIDerivedType(tag: DW_TAG_member, name: "gso_segs", scope: !148, file: !6, line: 4217, baseType: !22, size: 32, offset: 1312)
!215 = !DIDerivedType(tag: DW_TAG_member, scope: !148, file: !6, line: 4218, baseType: !216, size: 64, align: 64, offset: 1344)
!216 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !148, file: !6, line: 4218, size: 64, align: 64, elements: !217)
!217 = !{!218}
!218 = !DIDerivedType(tag: DW_TAG_member, name: "sk", scope: !216, file: !6, line: 4218, baseType: !219, size: 64)
!219 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !220, size: 64)
!220 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_sock", file: !6, line: 4272, size: 640, elements: !221)
!221 = !{!222, !223, !224, !225, !226, !227, !228, !229, !230, !231, !232, !233, !234, !235}
!222 = !DIDerivedType(tag: DW_TAG_member, name: "bound_dev_if", scope: !220, file: !6, line: 4273, baseType: !22, size: 32)
!223 = !DIDerivedType(tag: DW_TAG_member, name: "family", scope: !220, file: !6, line: 4274, baseType: !22, size: 32, offset: 32)
!224 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !220, file: !6, line: 4275, baseType: !22, size: 32, offset: 64)
!225 = !DIDerivedType(tag: DW_TAG_member, name: "protocol", scope: !220, file: !6, line: 4276, baseType: !22, size: 32, offset: 96)
!226 = !DIDerivedType(tag: DW_TAG_member, name: "mark", scope: !220, file: !6, line: 4277, baseType: !22, size: 32, offset: 128)
!227 = !DIDerivedType(tag: DW_TAG_member, name: "priority", scope: !220, file: !6, line: 4278, baseType: !22, size: 32, offset: 160)
!228 = !DIDerivedType(tag: DW_TAG_member, name: "src_ip4", scope: !220, file: !6, line: 4280, baseType: !22, size: 32, offset: 192)
!229 = !DIDerivedType(tag: DW_TAG_member, name: "src_ip6", scope: !220, file: !6, line: 4281, baseType: !175, size: 128, offset: 224)
!230 = !DIDerivedType(tag: DW_TAG_member, name: "src_port", scope: !220, file: !6, line: 4282, baseType: !22, size: 32, offset: 352)
!231 = !DIDerivedType(tag: DW_TAG_member, name: "dst_port", scope: !220, file: !6, line: 4283, baseType: !22, size: 32, offset: 384)
!232 = !DIDerivedType(tag: DW_TAG_member, name: "dst_ip4", scope: !220, file: !6, line: 4284, baseType: !22, size: 32, offset: 416)
!233 = !DIDerivedType(tag: DW_TAG_member, name: "dst_ip6", scope: !220, file: !6, line: 4285, baseType: !175, size: 128, offset: 448)
!234 = !DIDerivedType(tag: DW_TAG_member, name: "state", scope: !220, file: !6, line: 4286, baseType: !22, size: 32, offset: 576)
!235 = !DIDerivedType(tag: DW_TAG_member, name: "rx_queue_mapping", scope: !220, file: !6, line: 4287, baseType: !236, size: 32, offset: 608)
!236 = !DIDerivedType(tag: DW_TAG_typedef, name: "__s32", file: !20, line: 26, baseType: !69)
!237 = !DIDerivedType(tag: DW_TAG_member, name: "gso_size", scope: !148, file: !6, line: 4219, baseType: !22, size: 32, offset: 1408)
!238 = !DIGlobalVariableExpression(var: !239, expr: !DIExpression())
!239 = distinct !DIGlobalVariable(name: "bpf_redirect_neigh", scope: !2, file: !128, line: 3593, type: !240, isLocal: true, isDefinition: true)
!240 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !241, size: 64)
!241 = !DISubroutineType(types: !242)
!242 = !{!132, !22, !243, !69, !29}
!243 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !244, size: 64)
!244 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_redir_neigh", file: !6, line: 5016, size: 160, elements: !245)
!245 = !{!246, !247}
!246 = !DIDerivedType(tag: DW_TAG_member, name: "nh_family", scope: !244, file: !6, line: 5018, baseType: !22, size: 32)
!247 = !DIDerivedType(tag: DW_TAG_member, scope: !244, file: !6, line: 5020, baseType: !248, size: 128, offset: 32)
!248 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !244, file: !6, line: 5020, size: 128, elements: !249)
!249 = !{!250, !251}
!250 = !DIDerivedType(tag: DW_TAG_member, name: "ipv4_nh", scope: !248, file: !6, line: 5021, baseType: !24, size: 32)
!251 = !DIDerivedType(tag: DW_TAG_member, name: "ipv6_nh", scope: !248, file: !6, line: 5022, baseType: !175, size: 128)
!252 = !DIGlobalVariableExpression(var: !253, expr: !DIExpression())
!253 = distinct !DIGlobalVariable(name: "bpf_map_pop_elem", scope: !2, file: !128, line: 2245, type: !254, isLocal: true, isDefinition: true)
!254 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !255, size: 64)
!255 = !DISubroutineType(types: !256)
!256 = !{!132, !17, !17}
!257 = !DIGlobalVariableExpression(var: !258, expr: !DIExpression())
!258 = distinct !DIGlobalVariable(name: "bpf_for_each_map_elem", scope: !2, file: !128, line: 3864, type: !259, isLocal: true, isDefinition: true)
!259 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !260, size: 64)
!260 = !DISubroutineType(types: !261)
!261 = !{!132, !17, !17, !17, !29}
!262 = !DIGlobalVariableExpression(var: !263, expr: !DIExpression())
!263 = distinct !DIGlobalVariable(name: "bpf_map_delete_elem", scope: !2, file: !128, line: 82, type: !264, isLocal: true, isDefinition: true)
!264 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !265, size: 64)
!265 = !DISubroutineType(types: !266)
!266 = !{!132, !17, !140}
!267 = !DIGlobalVariableExpression(var: !268, expr: !DIExpression())
!268 = distinct !DIGlobalVariable(name: "bpf_map_push_elem", scope: !2, file: !128, line: 2235, type: !269, isLocal: true, isDefinition: true)
!269 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !270, size: 64)
!270 = !DISubroutineType(types: !271)
!271 = !{!132, !17, !140, !29}
!272 = !DIGlobalVariableExpression(var: !273, expr: !DIExpression())
!273 = distinct !DIGlobalVariable(name: "bpf_ktime_get_ns", scope: !2, file: !128, line: 108, type: !274, isLocal: true, isDefinition: true)
!274 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !275, size: 64)
!275 = !DISubroutineType(types: !276)
!276 = !{!29}
!277 = !DIGlobalVariableExpression(var: !278, expr: !DIExpression())
!278 = distinct !DIGlobalVariable(name: "bpf_map_update_elem", scope: !2, file: !128, line: 72, type: !279, isLocal: true, isDefinition: true)
!279 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !280, size: 64)
!280 = !DISubroutineType(types: !281)
!281 = !{!132, !17, !140, !140, !29}
!282 = !DIGlobalVariableExpression(var: !283, expr: !DIExpression())
!283 = distinct !DIGlobalVariable(name: "bpf_csum_diff", scope: !2, file: !128, line: 783, type: !284, isLocal: true, isDefinition: true)
!284 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !285, size: 64)
!285 = !DISubroutineType(types: !286)
!286 = !{!287, !23, !22, !23, !22, !289}
!287 = !DIDerivedType(tag: DW_TAG_typedef, name: "__s64", file: !20, line: 30, baseType: !288)
!288 = !DIBasicType(name: "long long int", size: 64, encoding: DW_ATE_signed)
!289 = !DIDerivedType(tag: DW_TAG_typedef, name: "__wsum", file: !25, line: 32, baseType: !22)
!290 = !DIGlobalVariableExpression(var: !291, expr: !DIExpression())
!291 = distinct !DIGlobalVariable(name: "bpf_redirect", scope: !2, file: !128, line: 608, type: !292, isLocal: true, isDefinition: true)
!292 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !293, size: 64)
!293 = !DISubroutineType(types: !294)
!294 = !{!132, !22, !29}
!295 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 32, elements: !56)
!296 = !{i32 7, !"Dwarf Version", i32 4}
!297 = !{i32 2, !"Debug Info Version", i32 3}
!298 = !{i32 1, !"wchar_size", i32 4}
!299 = !{i32 7, !"frame-pointer", i32 2}
!300 = !{!"Ubuntu clang version 13.0.0-2"}
!301 = distinct !DISubprogram(name: "nat64_egress", scope: !3, file: !3, line: 383, type: !302, scopeLine: 384, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !304)
!302 = !DISubroutineType(types: !303)
!303 = !{!69, !147}
!304 = !{!305}
!305 = !DILocalVariable(name: "skb", arg: 1, scope: !301, file: !3, line: 383, type: !147)
!306 = !DILocation(line: 0, scope: !301)
!307 = !DILocation(line: 385, column: 16, scope: !301)
!308 = !DILocation(line: 385, column: 9, scope: !301)
!309 = distinct !DISubprogram(name: "nat64_handler", scope: !3, file: !3, line: 365, type: !310, scopeLine: 366, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !313)
!310 = !DISubroutineType(types: !311)
!311 = !{!69, !147, !312}
!312 = !DIBasicType(name: "_Bool", size: 8, encoding: DW_ATE_boolean)
!313 = !{!314, !315, !316, !317, !318, !323, !334}
!314 = !DILocalVariable(name: "skb", arg: 1, scope: !309, file: !3, line: 365, type: !147)
!315 = !DILocalVariable(name: "egress", arg: 2, scope: !309, file: !3, line: 365, type: !312)
!316 = !DILocalVariable(name: "data_end", scope: !309, file: !3, line: 367, type: !17)
!317 = !DILocalVariable(name: "data", scope: !309, file: !3, line: 368, type: !17)
!318 = !DILocalVariable(name: "nh", scope: !309, file: !3, line: 369, type: !319)
!319 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "hdr_cursor", file: !320, line: 35, size: 64, elements: !321)
!320 = !DIFile(filename: "./../include/xdp/parsing_helpers.h", directory: "/home/sha68/bpf-examples/nat64-bpf")
!321 = !{!322}
!322 = !DIDerivedType(tag: DW_TAG_member, name: "pos", scope: !319, file: !320, line: 36, baseType: !17, size: 64)
!323 = !DILocalVariable(name: "eth", scope: !309, file: !3, line: 370, type: !324)
!324 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !325, size: 64)
!325 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ethhdr", file: !326, line: 165, size: 112, elements: !327)
!326 = !DIFile(filename: "/usr/include/linux/if_ether.h", directory: "")
!327 = !{!328, !332, !333}
!328 = !DIDerivedType(tag: DW_TAG_member, name: "h_dest", scope: !325, file: !326, line: 166, baseType: !329, size: 48)
!329 = !DICompositeType(tag: DW_TAG_array_type, baseType: !46, size: 48, elements: !330)
!330 = !{!331}
!331 = !DISubrange(count: 6)
!332 = !DIDerivedType(tag: DW_TAG_member, name: "h_source", scope: !325, file: !326, line: 167, baseType: !329, size: 48, offset: 48)
!333 = !DIDerivedType(tag: DW_TAG_member, name: "h_proto", scope: !325, file: !326, line: 168, baseType: !51, size: 16, offset: 96)
!334 = !DILocalVariable(name: "eth_type", scope: !309, file: !3, line: 371, type: !69)
!335 = !DILocation(line: 0, scope: !309)
!336 = !DILocation(line: 367, column: 52, scope: !309)
!337 = !{!338, !339, i64 80}
!338 = !{!"__sk_buff", !339, i64 0, !339, i64 4, !339, i64 8, !339, i64 12, !339, i64 16, !339, i64 20, !339, i64 24, !339, i64 28, !339, i64 32, !339, i64 36, !339, i64 40, !339, i64 44, !340, i64 48, !339, i64 68, !339, i64 72, !339, i64 76, !339, i64 80, !339, i64 84, !339, i64 88, !339, i64 92, !339, i64 96, !340, i64 100, !340, i64 116, !339, i64 132, !339, i64 136, !339, i64 140, !340, i64 144, !342, i64 152, !339, i64 160, !339, i64 164, !340, i64 168, !339, i64 176}
!339 = !{!"int", !340, i64 0}
!340 = !{!"omnipotent char", !341, i64 0}
!341 = !{!"Simple C/C++ TBAA"}
!342 = !{!"long long", !340, i64 0}
!343 = !DILocation(line: 367, column: 27, scope: !309)
!344 = !DILocation(line: 367, column: 19, scope: !309)
!345 = !DILocation(line: 368, column: 48, scope: !309)
!346 = !{!338, !339, i64 76}
!347 = !DILocation(line: 368, column: 23, scope: !309)
!348 = !DILocation(line: 368, column: 15, scope: !309)
!349 = !DILocalVariable(name: "nh", arg: 1, scope: !350, file: !320, line: 131, type: !353)
!350 = distinct !DISubprogram(name: "parse_ethhdr", scope: !320, file: !320, line: 131, type: !351, scopeLine: 134, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !355)
!351 = !DISubroutineType(types: !352)
!352 = !{!69, !353, !17, !354}
!353 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !319, size: 64)
!354 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !324, size: 64)
!355 = !{!349, !356, !357}
!356 = !DILocalVariable(name: "data_end", arg: 2, scope: !350, file: !320, line: 132, type: !17)
!357 = !DILocalVariable(name: "ethhdr", arg: 3, scope: !350, file: !320, line: 133, type: !354)
!358 = !DILocation(line: 0, scope: !350, inlinedAt: !359)
!359 = distinct !DILocation(line: 374, column: 13, scope: !309)
!360 = !DILocalVariable(name: "nh", arg: 1, scope: !361, file: !320, line: 86, type: !353)
!361 = distinct !DISubprogram(name: "parse_ethhdr_vlan", scope: !320, file: !320, line: 86, type: !362, scopeLine: 90, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !371)
!362 = !DISubroutineType(types: !363)
!363 = !{!69, !353, !17, !354, !364}
!364 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !365, size: 64)
!365 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "collect_vlans", file: !320, line: 71, size: 32, elements: !366)
!366 = !{!367}
!367 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !365, file: !320, line: 72, baseType: !368, size: 32)
!368 = !DICompositeType(tag: DW_TAG_array_type, baseType: !19, size: 32, elements: !369)
!369 = !{!370}
!370 = !DISubrange(count: 2)
!371 = !{!360, !372, !373, !374, !375, !376, !377, !383, !384}
!372 = !DILocalVariable(name: "data_end", arg: 2, scope: !361, file: !320, line: 87, type: !17)
!373 = !DILocalVariable(name: "ethhdr", arg: 3, scope: !361, file: !320, line: 88, type: !354)
!374 = !DILocalVariable(name: "vlans", arg: 4, scope: !361, file: !320, line: 89, type: !364)
!375 = !DILocalVariable(name: "eth", scope: !361, file: !320, line: 91, type: !324)
!376 = !DILocalVariable(name: "hdrsize", scope: !361, file: !320, line: 92, type: !69)
!377 = !DILocalVariable(name: "vlh", scope: !361, file: !320, line: 93, type: !378)
!378 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !379, size: 64)
!379 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "vlan_hdr", file: !320, line: 44, size: 32, elements: !380)
!380 = !{!381, !382}
!381 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_TCI", scope: !379, file: !320, line: 45, baseType: !51, size: 16)
!382 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_encapsulated_proto", scope: !379, file: !320, line: 46, baseType: !51, size: 16, offset: 16)
!383 = !DILocalVariable(name: "h_proto", scope: !361, file: !320, line: 94, type: !19)
!384 = !DILocalVariable(name: "i", scope: !361, file: !320, line: 95, type: !69)
!385 = !DILocation(line: 0, scope: !361, inlinedAt: !386)
!386 = distinct !DILocation(line: 136, column: 9, scope: !350, inlinedAt: !359)
!387 = !DILocation(line: 100, column: 14, scope: !388, inlinedAt: !386)
!388 = distinct !DILexicalBlock(scope: !361, file: !320, line: 100, column: 6)
!389 = !DILocation(line: 100, column: 24, scope: !388, inlinedAt: !386)
!390 = !DILocation(line: 100, column: 6, scope: !361, inlinedAt: !386)
!391 = !DILocation(line: 106, column: 17, scope: !361, inlinedAt: !386)
!392 = !{!393, !393, i64 0}
!393 = !{!"short", !340, i64 0}
!394 = !DILocalVariable(name: "h_proto", arg: 1, scope: !395, file: !320, line: 75, type: !19)
!395 = distinct !DISubprogram(name: "proto_is_vlan", scope: !320, file: !320, line: 75, type: !396, scopeLine: 76, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !398)
!396 = !DISubroutineType(types: !397)
!397 = !{!69, !19}
!398 = !{!394}
!399 = !DILocation(line: 0, scope: !395, inlinedAt: !400)
!400 = distinct !DILocation(line: 113, column: 8, scope: !401, inlinedAt: !386)
!401 = distinct !DILexicalBlock(scope: !402, file: !320, line: 113, column: 7)
!402 = distinct !DILexicalBlock(scope: !403, file: !320, line: 112, column: 39)
!403 = distinct !DILexicalBlock(scope: !404, file: !320, line: 112, column: 2)
!404 = distinct !DILexicalBlock(scope: !361, file: !320, line: 112, column: 2)
!405 = !DILocation(line: 77, column: 20, scope: !395, inlinedAt: !400)
!406 = !DILocation(line: 77, column: 46, scope: !395, inlinedAt: !400)
!407 = !DILocation(line: 113, column: 7, scope: !402, inlinedAt: !386)
!408 = !DILocation(line: 116, column: 11, scope: !409, inlinedAt: !386)
!409 = distinct !DILexicalBlock(scope: !402, file: !320, line: 116, column: 7)
!410 = !DILocation(line: 116, column: 15, scope: !409, inlinedAt: !386)
!411 = !DILocation(line: 116, column: 7, scope: !402, inlinedAt: !386)
!412 = !DILocation(line: 119, column: 18, scope: !402, inlinedAt: !386)
!413 = !DILocation(line: 375, column: 15, scope: !414)
!414 = distinct !DILexicalBlock(scope: !309, file: !3, line: 375, column: 6)
!415 = !DILocation(line: 375, column: 38, scope: !414)
!416 = !DILocalVariable(name: "dst_hdr", scope: !417, file: !3, line: 73, type: !431)
!417 = distinct !DISubprogram(name: "nat64_handle_v4", scope: !3, file: !3, line: 60, type: !418, scopeLine: 61, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !420)
!418 = !DISubroutineType(types: !419)
!419 = !{!69, !147, !353}
!420 = !{!421, !422, !423, !424, !425, !426, !427, !428, !429, !445, !446, !463, !464, !416, !465, !472, !479, !484}
!421 = !DILocalVariable(name: "skb", arg: 1, scope: !417, file: !3, line: 60, type: !147)
!422 = !DILocalVariable(name: "nh", arg: 2, scope: !417, file: !3, line: 60, type: !353)
!423 = !DILocalVariable(name: "data_end", scope: !417, file: !3, line: 62, type: !17)
!424 = !DILocalVariable(name: "data", scope: !417, file: !3, line: 63, type: !17)
!425 = !DILocalVariable(name: "ip_type", scope: !417, file: !3, line: 65, type: !69)
!426 = !DILocalVariable(name: "iphdr_len", scope: !417, file: !3, line: 65, type: !69)
!427 = !DILocalVariable(name: "ip_offset", scope: !417, file: !3, line: 65, type: !69)
!428 = !DILocalVariable(name: "dst_v6", scope: !417, file: !3, line: 66, type: !73)
!429 = !DILocalVariable(name: "ip6h", scope: !417, file: !3, line: 67, type: !430)
!430 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !431, size: 64)
!431 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ipv6hdr", file: !432, line: 117, size: 320, elements: !433)
!432 = !DIFile(filename: "/usr/include/linux/ipv6.h", directory: "")
!433 = !{!434, !435, !436, !440, !441, !442, !443, !444}
!434 = !DIDerivedType(tag: DW_TAG_member, name: "priority", scope: !431, file: !432, line: 119, baseType: !45, size: 4, flags: DIFlagBitField, extraData: i64 0)
!435 = !DIDerivedType(tag: DW_TAG_member, name: "version", scope: !431, file: !432, line: 120, baseType: !45, size: 4, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!436 = !DIDerivedType(tag: DW_TAG_member, name: "flow_lbl", scope: !431, file: !432, line: 127, baseType: !437, size: 24, offset: 8)
!437 = !DICompositeType(tag: DW_TAG_array_type, baseType: !45, size: 24, elements: !438)
!438 = !{!439}
!439 = !DISubrange(count: 3)
!440 = !DIDerivedType(tag: DW_TAG_member, name: "payload_len", scope: !431, file: !432, line: 129, baseType: !51, size: 16, offset: 32)
!441 = !DIDerivedType(tag: DW_TAG_member, name: "nexthdr", scope: !431, file: !432, line: 130, baseType: !45, size: 8, offset: 48)
!442 = !DIDerivedType(tag: DW_TAG_member, name: "hop_limit", scope: !431, file: !432, line: 131, baseType: !45, size: 8, offset: 56)
!443 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !431, file: !432, line: 133, baseType: !37, size: 128, offset: 64)
!444 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !431, file: !432, line: 134, baseType: !37, size: 128, offset: 192)
!445 = !DILocalVariable(name: "ret", scope: !417, file: !3, line: 68, type: !69)
!446 = !DILocalVariable(name: "iph", scope: !417, file: !3, line: 69, type: !447)
!447 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !448, size: 64)
!448 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "iphdr", file: !449, line: 86, size: 160, elements: !450)
!449 = !DIFile(filename: "/usr/include/linux/ip.h", directory: "")
!450 = !{!451, !452, !453, !454, !455, !456, !457, !458, !459, !461, !462}
!451 = !DIDerivedType(tag: DW_TAG_member, name: "ihl", scope: !448, file: !449, line: 88, baseType: !45, size: 4, flags: DIFlagBitField, extraData: i64 0)
!452 = !DIDerivedType(tag: DW_TAG_member, name: "version", scope: !448, file: !449, line: 89, baseType: !45, size: 4, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!453 = !DIDerivedType(tag: DW_TAG_member, name: "tos", scope: !448, file: !449, line: 96, baseType: !45, size: 8, offset: 8)
!454 = !DIDerivedType(tag: DW_TAG_member, name: "tot_len", scope: !448, file: !449, line: 97, baseType: !51, size: 16, offset: 16)
!455 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !448, file: !449, line: 98, baseType: !51, size: 16, offset: 32)
!456 = !DIDerivedType(tag: DW_TAG_member, name: "frag_off", scope: !448, file: !449, line: 99, baseType: !51, size: 16, offset: 48)
!457 = !DIDerivedType(tag: DW_TAG_member, name: "ttl", scope: !448, file: !449, line: 100, baseType: !45, size: 8, offset: 64)
!458 = !DIDerivedType(tag: DW_TAG_member, name: "protocol", scope: !448, file: !449, line: 101, baseType: !45, size: 8, offset: 72)
!459 = !DIDerivedType(tag: DW_TAG_member, name: "check", scope: !448, file: !449, line: 102, baseType: !460, size: 16, offset: 80)
!460 = !DIDerivedType(tag: DW_TAG_typedef, name: "__sum16", file: !25, line: 31, baseType: !19)
!461 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !448, file: !449, line: 103, baseType: !24, size: 32, offset: 96)
!462 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !448, file: !449, line: 104, baseType: !24, size: 32, offset: 128)
!463 = !DILocalVariable(name: "eth", scope: !417, file: !3, line: 70, type: !324)
!464 = !DILocalVariable(name: "dst_v4", scope: !417, file: !3, line: 71, type: !22)
!465 = !DILocalVariable(name: "____fmt", scope: !466, file: !3, line: 104, type: !469)
!466 = distinct !DILexicalBlock(scope: !467, file: !3, line: 104, column: 17)
!467 = distinct !DILexicalBlock(scope: !468, file: !3, line: 103, column: 50)
!468 = distinct !DILexicalBlock(scope: !417, file: !3, line: 102, column: 13)
!469 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 608, elements: !470)
!470 = !{!471}
!471 = !DISubrange(count: 76)
!472 = !DILocalVariable(name: "____fmt", scope: !473, file: !3, line: 112, type: !476)
!473 = distinct !DILexicalBlock(scope: !474, file: !3, line: 112, column: 17)
!474 = distinct !DILexicalBlock(scope: !475, file: !3, line: 111, column: 22)
!475 = distinct !DILexicalBlock(scope: !417, file: !3, line: 111, column: 13)
!476 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 336, elements: !477)
!477 = !{!478}
!478 = !DISubrange(count: 42)
!479 = !DILocalVariable(name: "____fmt", scope: !480, file: !3, line: 116, type: !481)
!480 = distinct !DILexicalBlock(scope: !417, file: !3, line: 116, column: 9)
!481 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 384, elements: !482)
!482 = !{!483}
!483 = !DISubrange(count: 48)
!484 = !DILabel(scope: !417, name: "out", file: !3, line: 143)
!485 = !DILocation(line: 73, column: 17, scope: !417, inlinedAt: !486)
!486 = distinct !DILocation(line: 376, column: 10, scope: !414)
!487 = !DILocation(line: 0, scope: !417, inlinedAt: !486)
!488 = !DILocation(line: 71, column: 9, scope: !417, inlinedAt: !486)
!489 = !DILocation(line: 73, column: 2, scope: !417, inlinedAt: !486)
!490 = !DILocation(line: 75, column: 19, scope: !417, inlinedAt: !486)
!491 = !{i64 0, i64 16, !492, i64 0, i64 16, !492, i64 0, i64 16, !492}
!492 = !{!340, !340, i64 0}
!493 = !DILocation(line: 78, column: 30, scope: !417, inlinedAt: !486)
!494 = !DILocation(line: 78, column: 21, scope: !417, inlinedAt: !486)
!495 = !DILocalVariable(name: "nh", arg: 1, scope: !496, file: !320, line: 196, type: !353)
!496 = distinct !DISubprogram(name: "parse_iphdr", scope: !320, file: !320, line: 196, type: !497, scopeLine: 199, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !500)
!497 = !DISubroutineType(types: !498)
!498 = !{!69, !353, !17, !499}
!499 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !447, size: 64)
!500 = !{!495, !501, !502, !503, !504}
!501 = !DILocalVariable(name: "data_end", arg: 2, scope: !496, file: !320, line: 197, type: !17)
!502 = !DILocalVariable(name: "iphdr", arg: 3, scope: !496, file: !320, line: 198, type: !499)
!503 = !DILocalVariable(name: "iph", scope: !496, file: !320, line: 200, type: !447)
!504 = !DILocalVariable(name: "hdrsize", scope: !496, file: !320, line: 201, type: !69)
!505 = !DILocation(line: 0, scope: !496, inlinedAt: !506)
!506 = distinct !DILocation(line: 80, column: 19, scope: !417, inlinedAt: !486)
!507 = !DILocation(line: 203, column: 10, scope: !508, inlinedAt: !506)
!508 = distinct !DILexicalBlock(scope: !496, file: !320, line: 203, column: 6)
!509 = !DILocation(line: 203, column: 14, scope: !508, inlinedAt: !506)
!510 = !DILocation(line: 203, column: 6, scope: !496, inlinedAt: !506)
!511 = !DILocation(line: 206, column: 11, scope: !512, inlinedAt: !506)
!512 = distinct !DILexicalBlock(scope: !496, file: !320, line: 206, column: 6)
!513 = !DILocation(line: 206, column: 19, scope: !512, inlinedAt: !506)
!514 = !DILocation(line: 206, column: 6, scope: !496, inlinedAt: !506)
!515 = !DILocation(line: 209, column: 21, scope: !496, inlinedAt: !506)
!516 = !DILocation(line: 211, column: 13, scope: !517, inlinedAt: !506)
!517 = distinct !DILexicalBlock(scope: !496, file: !320, line: 211, column: 5)
!518 = !DILocation(line: 211, column: 5, scope: !496, inlinedAt: !506)
!519 = !DILocation(line: 215, column: 14, scope: !520, inlinedAt: !506)
!520 = distinct !DILexicalBlock(scope: !496, file: !320, line: 215, column: 6)
!521 = !DILocation(line: 215, column: 24, scope: !520, inlinedAt: !506)
!522 = !DILocation(line: 215, column: 6, scope: !496, inlinedAt: !506)
!523 = !DILocation(line: 84, column: 18, scope: !417, inlinedAt: !486)
!524 = !{!525, !339, i64 16}
!525 = !{!"iphdr", !340, i64 0, !340, i64 0, !340, i64 1, !393, i64 2, !393, i64 4, !393, i64 6, !340, i64 8, !340, i64 9, !393, i64 10, !339, i64 12, !339, i64 16}
!526 = !DILocation(line: 84, column: 16, scope: !417, inlinedAt: !486)
!527 = !{!339, !339, i64 0}
!528 = !DILocation(line: 85, column: 30, scope: !529, inlinedAt: !486)
!529 = distinct !DILexicalBlock(scope: !417, file: !3, line: 85, column: 13)
!530 = !{!531, !339, i64 36}
!531 = !{!"nat64_config", !532, i64 0, !342, i64 16, !342, i64 24, !339, i64 32, !339, i64 36}
!532 = !{!"in6_addr", !340, i64 0}
!533 = !DILocation(line: 85, column: 21, scope: !529, inlinedAt: !486)
!534 = !DILocation(line: 85, column: 49, scope: !529, inlinedAt: !486)
!535 = !{!531, !339, i64 32}
!536 = !DILocation(line: 85, column: 39, scope: !529, inlinedAt: !486)
!537 = !DILocation(line: 85, column: 13, scope: !417, inlinedAt: !486)
!538 = !DILocation(line: 101, column: 26, scope: !417, inlinedAt: !486)
!539 = !DILocation(line: 102, column: 23, scope: !468, inlinedAt: !486)
!540 = !DILocation(line: 102, column: 47, scope: !468, inlinedAt: !486)
!541 = !DILocation(line: 103, column: 19, scope: !468, inlinedAt: !486)
!542 = !{!525, !393, i64 6}
!543 = !DILocation(line: 103, column: 28, scope: !468, inlinedAt: !486)
!544 = !DILocation(line: 102, column: 13, scope: !417, inlinedAt: !486)
!545 = !DILocation(line: 104, column: 17, scope: !466, inlinedAt: !486)
!546 = !DILocation(line: 104, column: 17, scope: !467, inlinedAt: !486)
!547 = !DILocation(line: 106, column: 17, scope: !467, inlinedAt: !486)
!548 = !DILocation(line: 110, column: 18, scope: !417, inlinedAt: !486)
!549 = !DILocation(line: 111, column: 14, scope: !475, inlinedAt: !486)
!550 = !DILocation(line: 111, column: 13, scope: !417, inlinedAt: !486)
!551 = !DILocation(line: 112, column: 17, scope: !473, inlinedAt: !486)
!552 = !DILocation(line: 112, column: 17, scope: !474, inlinedAt: !486)
!553 = !DILocation(line: 113, column: 17, scope: !474, inlinedAt: !486)
!554 = !DILocation(line: 116, column: 9, scope: !480, inlinedAt: !486)
!555 = !DILocation(line: 116, column: 9, scope: !417, inlinedAt: !486)
!556 = !DILocation(line: 119, column: 43, scope: !417, inlinedAt: !486)
!557 = !{!525, !339, i64 12}
!558 = !DILocation(line: 120, column: 25, scope: !417, inlinedAt: !486)
!559 = !DILocation(line: 121, column: 32, scope: !417, inlinedAt: !486)
!560 = !{!525, !340, i64 9}
!561 = !DILocation(line: 122, column: 34, scope: !417, inlinedAt: !486)
!562 = !{!525, !340, i64 8}
!563 = !DILocation(line: 124, column: 34, scope: !417, inlinedAt: !486)
!564 = !{!525, !340, i64 1}
!565 = !DILocation(line: 124, column: 46, scope: !417, inlinedAt: !486)
!566 = !DILocation(line: 124, column: 26, scope: !417, inlinedAt: !486)
!567 = !DILocation(line: 125, column: 40, scope: !417, inlinedAt: !486)
!568 = !DILocation(line: 126, column: 31, scope: !417, inlinedAt: !486)
!569 = !{!525, !393, i64 2}
!570 = !DILocation(line: 128, column: 13, scope: !571, inlinedAt: !486)
!571 = distinct !DILexicalBlock(scope: !417, file: !3, line: 128, column: 13)
!572 = !DILocation(line: 128, column: 13, scope: !417, inlinedAt: !486)
!573 = !DILocation(line: 131, column: 42, scope: !417, inlinedAt: !486)
!574 = !DILocation(line: 131, column: 17, scope: !417, inlinedAt: !486)
!575 = !DILocation(line: 131, column: 9, scope: !417, inlinedAt: !486)
!576 = !DILocation(line: 132, column: 46, scope: !417, inlinedAt: !486)
!577 = !DILocation(line: 132, column: 21, scope: !417, inlinedAt: !486)
!578 = !DILocation(line: 134, column: 15, scope: !417, inlinedAt: !486)
!579 = !DILocation(line: 135, column: 21, scope: !417, inlinedAt: !486)
!580 = !DILocation(line: 136, column: 17, scope: !581, inlinedAt: !486)
!581 = distinct !DILexicalBlock(scope: !417, file: !3, line: 136, column: 13)
!582 = !DILocation(line: 136, column: 23, scope: !581, inlinedAt: !486)
!583 = !DILocation(line: 136, column: 21, scope: !581, inlinedAt: !486)
!584 = !DILocation(line: 136, column: 32, scope: !581, inlinedAt: !486)
!585 = !DILocation(line: 136, column: 40, scope: !581, inlinedAt: !486)
!586 = !DILocation(line: 136, column: 46, scope: !581, inlinedAt: !486)
!587 = !DILocation(line: 136, column: 44, scope: !581, inlinedAt: !486)
!588 = !DILocation(line: 136, column: 13, scope: !417, inlinedAt: !486)
!589 = !DILocation(line: 139, column: 14, scope: !417, inlinedAt: !486)
!590 = !DILocation(line: 139, column: 22, scope: !417, inlinedAt: !486)
!591 = !{!592, !393, i64 12}
!592 = !{!"ethhdr", !340, i64 0, !340, i64 6, !393, i64 12}
!593 = !DILocation(line: 140, column: 17, scope: !417, inlinedAt: !486)
!594 = !{i64 0, i64 1, !492, i64 0, i64 1, !492, i64 1, i64 3, !492, i64 4, i64 2, !392, i64 6, i64 1, !492, i64 7, i64 1, !492, i64 8, i64 16, !492, i64 8, i64 16, !492, i64 8, i64 16, !492, i64 24, i64 16, !492, i64 24, i64 16, !492, i64 24, i64 16, !492}
!595 = !{i64 0, i64 3, !492, i64 3, i64 2, !392, i64 5, i64 1, !492, i64 6, i64 1, !492, i64 7, i64 16, !492, i64 7, i64 16, !492, i64 7, i64 16, !492, i64 23, i64 16, !492, i64 23, i64 16, !492, i64 23, i64 16, !492}
!596 = !{i64 0, i64 2, !392, i64 2, i64 1, !492, i64 3, i64 1, !492, i64 4, i64 16, !492, i64 4, i64 16, !492, i64 4, i64 16, !492, i64 20, i64 16, !492, i64 20, i64 16, !492, i64 20, i64 16, !492}
!597 = !{i64 0, i64 1, !492, i64 1, i64 1, !492, i64 2, i64 16, !492, i64 2, i64 16, !492, i64 2, i64 16, !492, i64 18, i64 16, !492, i64 18, i64 16, !492, i64 18, i64 16, !492}
!598 = !{i64 0, i64 1, !492, i64 1, i64 16, !492, i64 1, i64 16, !492, i64 1, i64 16, !492, i64 17, i64 16, !492, i64 17, i64 16, !492, i64 17, i64 16, !492}
!599 = !{i64 0, i64 16, !492, i64 0, i64 16, !492, i64 0, i64 16, !492, i64 16, i64 16, !492, i64 16, i64 16, !492, i64 16, i64 16, !492}
!600 = !{i64 0, i64 4, !492, i64 0, i64 4, !492, i64 0, i64 4, !492, i64 4, i64 16, !492, i64 4, i64 16, !492, i64 4, i64 16, !492}
!601 = !DILocation(line: 142, column: 39, scope: !417, inlinedAt: !486)
!602 = !{!338, !339, i64 40}
!603 = !DILocation(line: 142, column: 15, scope: !417, inlinedAt: !486)
!604 = !DILocation(line: 142, column: 9, scope: !417, inlinedAt: !486)
!605 = !DILocation(line: 143, column: 1, scope: !417, inlinedAt: !486)
!606 = !DILocation(line: 145, column: 1, scope: !417, inlinedAt: !486)
!607 = !DILocation(line: 376, column: 3, scope: !414)
!608 = !DILocation(line: 377, column: 20, scope: !609)
!609 = distinct !DILexicalBlock(scope: !414, file: !3, line: 377, column: 11)
!610 = !DILocation(line: 377, column: 45, scope: !609)
!611 = !DILocalVariable(name: "skb", arg: 1, scope: !612, file: !3, line: 248, type: !147)
!612 = distinct !DISubprogram(name: "nat64_handle_v6", scope: !3, file: !3, line: 248, type: !418, scopeLine: 249, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !613)
!613 = !{!611, !614, !615, !616, !617, !627, !628, !629, !630, !631, !632, !633, !634, !635, !636, !637, !638, !639, !640, !647, !654, !661, !668, !677, !679, !682}
!614 = !DILocalVariable(name: "nh", arg: 2, scope: !612, file: !3, line: 248, type: !353)
!615 = !DILocalVariable(name: "data_end", scope: !612, file: !3, line: 250, type: !17)
!616 = !DILocalVariable(name: "data", scope: !612, file: !3, line: 251, type: !17)
!617 = !DILocalVariable(name: "saddr_key", scope: !612, file: !3, line: 253, type: !618)
!618 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "v6_trie_key", file: !34, line: 20, size: 160, elements: !619)
!619 = !{!620, !626}
!620 = !DIDerivedType(tag: DW_TAG_member, name: "t", scope: !618, file: !34, line: 21, baseType: !621, size: 32)
!621 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_lpm_trie_key", file: !6, line: 74, size: 32, elements: !622)
!622 = !{!623, !624}
!623 = !DIDerivedType(tag: DW_TAG_member, name: "prefixlen", scope: !621, file: !6, line: 75, baseType: !22, size: 32)
!624 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !621, file: !6, line: 76, baseType: !625, offset: 32)
!625 = !DICompositeType(tag: DW_TAG_array_type, baseType: !45, elements: !122)
!626 = !DIDerivedType(tag: DW_TAG_member, name: "addr", scope: !618, file: !34, line: 22, baseType: !37, size: 128, offset: 32)
!627 = !DILocalVariable(name: "dst_v6", scope: !612, file: !3, line: 254, type: !73)
!628 = !DILocalVariable(name: "subnet_v6", scope: !612, file: !3, line: 254, type: !37)
!629 = !DILocalVariable(name: "allowval", scope: !612, file: !3, line: 255, type: !89)
!630 = !DILocalVariable(name: "src_v4", scope: !612, file: !3, line: 255, type: !22)
!631 = !DILocalVariable(name: "dst_v4", scope: !612, file: !3, line: 255, type: !22)
!632 = !DILocalVariable(name: "ip_type", scope: !612, file: !3, line: 256, type: !69)
!633 = !DILocalVariable(name: "ip_offset", scope: !612, file: !3, line: 256, type: !69)
!634 = !DILocalVariable(name: "ip6h", scope: !612, file: !3, line: 257, type: !430)
!635 = !DILocalVariable(name: "ret", scope: !612, file: !3, line: 258, type: !69)
!636 = !DILocalVariable(name: "eth", scope: !612, file: !3, line: 259, type: !324)
!637 = !DILocalVariable(name: "iph", scope: !612, file: !3, line: 260, type: !447)
!638 = !DILocalVariable(name: "v6_state", scope: !612, file: !3, line: 262, type: !75)
!639 = !DILocalVariable(name: "dst_hdr", scope: !612, file: !3, line: 264, type: !448)
!640 = !DILocalVariable(name: "____fmt", scope: !641, file: !3, line: 281, type: !644)
!641 = distinct !DILexicalBlock(scope: !642, file: !3, line: 281, column: 17)
!642 = distinct !DILexicalBlock(scope: !643, file: !3, line: 280, column: 56)
!643 = distinct !DILexicalBlock(scope: !612, file: !3, line: 280, column: 13)
!644 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 480, elements: !645)
!645 = !{!646}
!646 = !DISubrange(count: 60)
!647 = !DILocalVariable(name: "____fmt", scope: !648, file: !3, line: 294, type: !651)
!648 = distinct !DILexicalBlock(scope: !649, file: !3, line: 294, column: 17)
!649 = distinct !DILexicalBlock(scope: !650, file: !3, line: 293, column: 39)
!650 = distinct !DILexicalBlock(scope: !612, file: !3, line: 293, column: 13)
!651 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 440, elements: !652)
!652 = !{!653}
!653 = !DISubrange(count: 55)
!654 = !DILocalVariable(name: "____fmt", scope: !655, file: !3, line: 304, type: !658)
!655 = distinct !DILexicalBlock(scope: !656, file: !3, line: 304, column: 17)
!656 = distinct !DILexicalBlock(scope: !657, file: !3, line: 303, column: 72)
!657 = distinct !DILexicalBlock(scope: !612, file: !3, line: 301, column: 13)
!658 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 416, elements: !659)
!659 = !{!660}
!660 = !DISubrange(count: 52)
!661 = !DILocalVariable(name: "____fmt", scope: !662, file: !3, line: 312, type: !665)
!662 = distinct !DILexicalBlock(scope: !663, file: !3, line: 312, column: 17)
!663 = distinct !DILexicalBlock(scope: !664, file: !3, line: 311, column: 24)
!664 = distinct !DILexicalBlock(scope: !612, file: !3, line: 311, column: 13)
!665 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 344, elements: !666)
!666 = !{!667}
!667 = !DISubrange(count: 43)
!668 = !DILocalVariable(name: "____fmt", scope: !669, file: !3, line: 320, type: !674)
!669 = distinct !DILexicalBlock(scope: !670, file: !3, line: 320, column: 25)
!670 = distinct !DILexicalBlock(scope: !671, file: !3, line: 319, column: 32)
!671 = distinct !DILexicalBlock(scope: !672, file: !3, line: 319, column: 21)
!672 = distinct !DILexicalBlock(scope: !673, file: !3, line: 317, column: 24)
!673 = distinct !DILexicalBlock(scope: !612, file: !3, line: 317, column: 13)
!674 = !DICompositeType(tag: DW_TAG_array_type, baseType: !27, size: 408, elements: !675)
!675 = !{!676}
!676 = !DISubrange(count: 51)
!677 = !DILocalVariable(name: "____fmt", scope: !678, file: !3, line: 325, type: !674)
!678 = distinct !DILexicalBlock(scope: !672, file: !3, line: 325, column: 17)
!679 = !DILocalVariable(name: "____fmt", scope: !680, file: !3, line: 332, type: !674)
!680 = distinct !DILexicalBlock(scope: !681, file: !3, line: 332, column: 17)
!681 = distinct !DILexicalBlock(scope: !673, file: !3, line: 327, column: 16)
!682 = !DILabel(scope: !612, name: "out", file: !3, line: 361)
!683 = !DILocation(line: 0, scope: !612, inlinedAt: !684)
!684 = distinct !DILocation(line: 378, column: 10, scope: !609)
!685 = !DILocation(line: 253, column: 2, scope: !612, inlinedAt: !684)
!686 = !DILocation(line: 253, column: 21, scope: !612, inlinedAt: !684)
!687 = !DILocation(line: 254, column: 9, scope: !612, inlinedAt: !684)
!688 = !DILocation(line: 254, column: 34, scope: !612, inlinedAt: !684)
!689 = !DILocation(line: 255, column: 9, scope: !612, inlinedAt: !684)
!690 = !DILocation(line: 264, column: 2, scope: !612, inlinedAt: !684)
!691 = !DILocation(line: 264, column: 15, scope: !612, inlinedAt: !684)
!692 = !DILocation(line: 270, column: 30, scope: !612, inlinedAt: !684)
!693 = !DILocation(line: 270, column: 21, scope: !612, inlinedAt: !684)
!694 = !DILocalVariable(name: "nh", arg: 1, scope: !695, file: !320, line: 174, type: !353)
!695 = distinct !DISubprogram(name: "parse_ip6hdr", scope: !320, file: !320, line: 174, type: !696, scopeLine: 177, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !699)
!696 = !DISubroutineType(types: !697)
!697 = !{!69, !353, !17, !698}
!698 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !430, size: 64)
!699 = !{!694, !700, !701, !702}
!700 = !DILocalVariable(name: "data_end", arg: 2, scope: !695, file: !320, line: 175, type: !17)
!701 = !DILocalVariable(name: "ip6hdr", arg: 3, scope: !695, file: !320, line: 176, type: !698)
!702 = !DILocalVariable(name: "ip6h", scope: !695, file: !320, line: 178, type: !430)
!703 = !DILocation(line: 0, scope: !695, inlinedAt: !704)
!704 = distinct !DILocation(line: 272, column: 19, scope: !612, inlinedAt: !684)
!705 = !DILocation(line: 184, column: 11, scope: !706, inlinedAt: !704)
!706 = distinct !DILexicalBlock(scope: !695, file: !320, line: 184, column: 6)
!707 = !DILocation(line: 184, column: 15, scope: !706, inlinedAt: !704)
!708 = !DILocation(line: 184, column: 6, scope: !695, inlinedAt: !704)
!709 = !DILocation(line: 187, column: 12, scope: !710, inlinedAt: !704)
!710 = distinct !DILexicalBlock(scope: !695, file: !320, line: 187, column: 6)
!711 = !DILocation(line: 187, column: 20, scope: !710, inlinedAt: !704)
!712 = !DILocation(line: 187, column: 6, scope: !695, inlinedAt: !704)
!713 = !DILocation(line: 193, column: 44, scope: !695, inlinedAt: !704)
!714 = !{!715, !340, i64 6}
!715 = !{!"ipv6hdr", !340, i64 0, !340, i64 0, !340, i64 1, !393, i64 4, !340, i64 6, !340, i64 7, !532, i64 8, !532, i64 24}
!716 = !DILocalVariable(name: "nh", arg: 1, scope: !717, file: !320, line: 139, type: !353)
!717 = distinct !DISubprogram(name: "skip_ip6hdrext", scope: !320, file: !320, line: 139, type: !718, scopeLine: 142, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !720)
!718 = !DISubroutineType(types: !719)
!719 = !{!69, !353, !17, !45}
!720 = !{!716, !721, !722, !723, !725}
!721 = !DILocalVariable(name: "data_end", arg: 2, scope: !717, file: !320, line: 140, type: !17)
!722 = !DILocalVariable(name: "next_hdr_type", arg: 3, scope: !717, file: !320, line: 141, type: !45)
!723 = !DILocalVariable(name: "i", scope: !724, file: !320, line: 143, type: !69)
!724 = distinct !DILexicalBlock(scope: !717, file: !320, line: 143, column: 2)
!725 = !DILocalVariable(name: "hdr", scope: !726, file: !320, line: 144, type: !728)
!726 = distinct !DILexicalBlock(scope: !727, file: !320, line: 143, column: 47)
!727 = distinct !DILexicalBlock(scope: !724, file: !320, line: 143, column: 2)
!728 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !729, size: 64)
!729 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ipv6_opt_hdr", file: !432, line: 62, size: 16, elements: !730)
!730 = !{!731, !732}
!731 = !DIDerivedType(tag: DW_TAG_member, name: "nexthdr", scope: !729, file: !432, line: 63, baseType: !45, size: 8)
!732 = !DIDerivedType(tag: DW_TAG_member, name: "hdrlen", scope: !729, file: !432, line: 64, baseType: !45, size: 8, offset: 8)
!733 = !DILocation(line: 0, scope: !717, inlinedAt: !734)
!734 = distinct !DILocation(line: 193, column: 9, scope: !695, inlinedAt: !704)
!735 = !DILocation(line: 0, scope: !724, inlinedAt: !734)
!736 = !DILocation(line: 0, scope: !726, inlinedAt: !734)
!737 = !DILocation(line: 146, column: 11, scope: !738, inlinedAt: !734)
!738 = distinct !DILexicalBlock(scope: !726, file: !320, line: 146, column: 7)
!739 = !DILocation(line: 146, column: 15, scope: !738, inlinedAt: !734)
!740 = !DILocation(line: 146, column: 7, scope: !726, inlinedAt: !734)
!741 = !DILocation(line: 149, column: 3, scope: !726, inlinedAt: !734)
!742 = !DILocation(line: 160, column: 4, scope: !743, inlinedAt: !734)
!743 = distinct !DILexicalBlock(scope: !726, file: !320, line: 149, column: 26)
!744 = !DILocation(line: 0, scope: !743, inlinedAt: !734)
!745 = !{!746, !340, i64 1}
!746 = !{!"ipv6_opt_hdr", !340, i64 0, !340, i64 1}
!747 = !{!746, !340, i64 0}
!748 = !DILocation(line: 156, column: 4, scope: !743, inlinedAt: !734)
!749 = !DILocation(line: 276, column: 25, scope: !612, inlinedAt: !684)
!750 = !DILocation(line: 277, column: 21, scope: !612, inlinedAt: !684)
!751 = !DILocation(line: 279, column: 9, scope: !612, inlinedAt: !684)
!752 = !DILocation(line: 279, column: 32, scope: !612, inlinedAt: !684)
!753 = !DILocalVariable(name: "a", arg: 1, scope: !754, file: !3, line: 228, type: !73)
!754 = distinct !DISubprogram(name: "cmp_v6addr", scope: !3, file: !3, line: 228, type: !755, scopeLine: 229, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !757)
!755 = !DISubroutineType(types: !756)
!756 = !{!69, !73, !73}
!757 = !{!753, !758, !759}
!758 = !DILocalVariable(name: "b", arg: 2, scope: !754, file: !3, line: 228, type: !73)
!759 = !DILocalVariable(name: "i", scope: !754, file: !3, line: 230, type: !69)
!760 = !DILocation(line: 0, scope: !754, inlinedAt: !761)
!761 = distinct !DILocation(line: 280, column: 13, scope: !643, inlinedAt: !684)
!762 = !DILocation(line: 232, column: 21, scope: !763, inlinedAt: !761)
!763 = distinct !DILexicalBlock(scope: !764, file: !3, line: 232, column: 21)
!764 = distinct !DILexicalBlock(scope: !765, file: !3, line: 231, column: 33)
!765 = distinct !DILexicalBlock(scope: !766, file: !3, line: 231, column: 9)
!766 = distinct !DILexicalBlock(scope: !754, file: !3, line: 231, column: 9)
!767 = !DILocation(line: 232, column: 39, scope: !763, inlinedAt: !761)
!768 = !DILocation(line: 232, column: 21, scope: !764, inlinedAt: !761)
!769 = !DILocation(line: 281, column: 17, scope: !641, inlinedAt: !684)
!770 = !DILocation(line: 281, column: 17, scope: !642, inlinedAt: !684)
!771 = !DILocation(line: 283, column: 17, scope: !642, inlinedAt: !684)
!772 = !DILocation(line: 293, column: 30, scope: !650, inlinedAt: !684)
!773 = !DILocation(line: 293, column: 21, scope: !650, inlinedAt: !684)
!774 = !DILocation(line: 293, column: 13, scope: !612, inlinedAt: !684)
!775 = !DILocation(line: 294, column: 17, scope: !648, inlinedAt: !684)
!776 = !DILocation(line: 294, column: 17, scope: !649, inlinedAt: !684)
!777 = !DILocation(line: 296, column: 17, scope: !649, inlinedAt: !684)
!778 = !DILocation(line: 300, column: 18, scope: !612, inlinedAt: !684)
!779 = !DILocation(line: 300, column: 16, scope: !612, inlinedAt: !684)
!780 = !DILocation(line: 301, column: 14, scope: !657, inlinedAt: !684)
!781 = !DILocation(line: 301, column: 21, scope: !657, inlinedAt: !684)
!782 = !DILocation(line: 304, column: 17, scope: !655, inlinedAt: !684)
!783 = !DILocation(line: 304, column: 17, scope: !656, inlinedAt: !684)
!784 = !DILocation(line: 306, column: 17, scope: !656, inlinedAt: !684)
!785 = !DILocation(line: 309, column: 19, scope: !612, inlinedAt: !684)
!786 = !DILocation(line: 309, column: 32, scope: !612, inlinedAt: !684)
!787 = !DILocation(line: 310, column: 20, scope: !612, inlinedAt: !684)
!788 = !DILocation(line: 311, column: 14, scope: !664, inlinedAt: !684)
!789 = !DILocation(line: 311, column: 13, scope: !612, inlinedAt: !684)
!790 = !DILocation(line: 312, column: 17, scope: !662, inlinedAt: !684)
!791 = !DILocation(line: 312, column: 17, scope: !663, inlinedAt: !684)
!792 = !DILocation(line: 313, column: 17, scope: !663, inlinedAt: !684)
!793 = !DILocation(line: 316, column: 20, scope: !612, inlinedAt: !684)
!794 = !DILocation(line: 317, column: 14, scope: !673, inlinedAt: !684)
!795 = !DILocation(line: 317, column: 13, scope: !612, inlinedAt: !684)
!796 = !DILocation(line: 318, column: 28, scope: !672, inlinedAt: !684)
!797 = !DILocation(line: 319, column: 22, scope: !671, inlinedAt: !684)
!798 = !DILocation(line: 319, column: 21, scope: !672, inlinedAt: !684)
!799 = !DILocation(line: 320, column: 25, scope: !669, inlinedAt: !684)
!800 = !DILocation(line: 320, column: 25, scope: !670, inlinedAt: !684)
!801 = !DILocation(line: 322, column: 25, scope: !670, inlinedAt: !684)
!802 = !DILocation(line: 324, column: 26, scope: !672, inlinedAt: !684)
!803 = !{!804, !339, i64 8}
!804 = !{!"v6_addr_state", !342, i64 0, !339, i64 8, !339, i64 12}
!805 = !DILocation(line: 324, column: 24, scope: !672, inlinedAt: !684)
!806 = !DILocation(line: 325, column: 17, scope: !678, inlinedAt: !684)
!807 = !DILocation(line: 325, column: 17, scope: !672, inlinedAt: !684)
!808 = !DILocation(line: 327, column: 9, scope: !672, inlinedAt: !684)
!809 = !DILocation(line: 328, column: 39, scope: !681, inlinedAt: !684)
!810 = !DILocation(line: 328, column: 27, scope: !681, inlinedAt: !684)
!811 = !DILocation(line: 328, column: 37, scope: !681, inlinedAt: !684)
!812 = !{!804, !342, i64 0}
!813 = !DILocation(line: 329, column: 17, scope: !681, inlinedAt: !684)
!814 = !DILocation(line: 331, column: 26, scope: !681, inlinedAt: !684)
!815 = !DILocation(line: 331, column: 24, scope: !681, inlinedAt: !684)
!816 = !DILocation(line: 332, column: 17, scope: !680, inlinedAt: !684)
!817 = !DILocation(line: 332, column: 17, scope: !681, inlinedAt: !684)
!818 = !DILocation(line: 336, column: 17, scope: !612, inlinedAt: !684)
!819 = !DILocation(line: 336, column: 23, scope: !612, inlinedAt: !684)
!820 = !DILocation(line: 337, column: 25, scope: !612, inlinedAt: !684)
!821 = !DILocation(line: 337, column: 17, scope: !612, inlinedAt: !684)
!822 = !DILocation(line: 337, column: 23, scope: !612, inlinedAt: !684)
!823 = !DILocation(line: 338, column: 34, scope: !612, inlinedAt: !684)
!824 = !DILocation(line: 338, column: 17, scope: !612, inlinedAt: !684)
!825 = !DILocation(line: 338, column: 26, scope: !612, inlinedAt: !684)
!826 = !DILocation(line: 339, column: 29, scope: !612, inlinedAt: !684)
!827 = !{!715, !340, i64 7}
!828 = !DILocation(line: 339, column: 17, scope: !612, inlinedAt: !684)
!829 = !DILocation(line: 339, column: 21, scope: !612, inlinedAt: !684)
!830 = !DILocation(line: 340, column: 29, scope: !612, inlinedAt: !684)
!831 = !DILocation(line: 340, column: 46, scope: !612, inlinedAt: !684)
!832 = !DILocation(line: 340, column: 43, scope: !612, inlinedAt: !684)
!833 = !DILocation(line: 340, column: 17, scope: !612, inlinedAt: !684)
!834 = !DILocation(line: 340, column: 21, scope: !612, inlinedAt: !684)
!835 = !DILocation(line: 341, column: 27, scope: !612, inlinedAt: !684)
!836 = !{!715, !393, i64 4}
!837 = !DILocation(line: 341, column: 17, scope: !612, inlinedAt: !684)
!838 = !DILocation(line: 341, column: 25, scope: !612, inlinedAt: !684)
!839 = !DILocation(line: 342, column: 56, scope: !612, inlinedAt: !684)
!840 = !DILocation(line: 342, column: 42, scope: !612, inlinedAt: !684)
!841 = !DILocalVariable(name: "csum", arg: 1, scope: !842, file: !3, line: 240, type: !22)
!842 = distinct !DISubprogram(name: "csum_fold_helper", scope: !3, file: !3, line: 240, type: !843, scopeLine: 241, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !845)
!843 = !DISubroutineType(types: !844)
!844 = !{!19, !22}
!845 = !{!841, !846}
!846 = !DILocalVariable(name: "sum", scope: !842, file: !3, line: 242, type: !22)
!847 = !DILocation(line: 0, scope: !842, inlinedAt: !848)
!848 = distinct !DILocation(line: 342, column: 25, scope: !612, inlinedAt: !684)
!849 = !DILocation(line: 243, column: 14, scope: !842, inlinedAt: !848)
!850 = !DILocation(line: 243, column: 29, scope: !842, inlinedAt: !848)
!851 = !DILocation(line: 243, column: 21, scope: !842, inlinedAt: !848)
!852 = !DILocation(line: 244, column: 14, scope: !842, inlinedAt: !848)
!853 = !DILocation(line: 244, column: 6, scope: !842, inlinedAt: !848)
!854 = !DILocation(line: 245, column: 9, scope: !842, inlinedAt: !848)
!855 = !DILocation(line: 342, column: 17, scope: !612, inlinedAt: !684)
!856 = !DILocation(line: 342, column: 23, scope: !612, inlinedAt: !684)
!857 = !{!525, !393, i64 10}
!858 = !DILocation(line: 346, column: 13, scope: !859, inlinedAt: !684)
!859 = distinct !DILexicalBlock(scope: !612, file: !3, line: 346, column: 13)
!860 = !DILocation(line: 346, column: 13, scope: !612, inlinedAt: !684)
!861 = !DILocation(line: 349, column: 42, scope: !612, inlinedAt: !684)
!862 = !DILocation(line: 349, column: 17, scope: !612, inlinedAt: !684)
!863 = !DILocation(line: 349, column: 9, scope: !612, inlinedAt: !684)
!864 = !DILocation(line: 350, column: 46, scope: !612, inlinedAt: !684)
!865 = !DILocation(line: 350, column: 21, scope: !612, inlinedAt: !684)
!866 = !DILocation(line: 352, column: 15, scope: !612, inlinedAt: !684)
!867 = !DILocation(line: 353, column: 20, scope: !612, inlinedAt: !684)
!868 = !DILocation(line: 354, column: 17, scope: !869, inlinedAt: !684)
!869 = distinct !DILexicalBlock(scope: !612, file: !3, line: 354, column: 13)
!870 = !DILocation(line: 354, column: 23, scope: !869, inlinedAt: !684)
!871 = !DILocation(line: 354, column: 21, scope: !869, inlinedAt: !684)
!872 = !DILocation(line: 354, column: 32, scope: !869, inlinedAt: !684)
!873 = !DILocation(line: 354, column: 39, scope: !869, inlinedAt: !684)
!874 = !DILocation(line: 354, column: 45, scope: !869, inlinedAt: !684)
!875 = !DILocation(line: 354, column: 43, scope: !869, inlinedAt: !684)
!876 = !DILocation(line: 354, column: 13, scope: !612, inlinedAt: !684)
!877 = !DILocation(line: 357, column: 14, scope: !612, inlinedAt: !684)
!878 = !DILocation(line: 357, column: 22, scope: !612, inlinedAt: !684)
!879 = !DILocation(line: 358, column: 16, scope: !612, inlinedAt: !684)
!880 = !{i64 0, i64 1, !492, i64 0, i64 1, !492, i64 1, i64 1, !492, i64 2, i64 2, !392, i64 4, i64 2, !392, i64 6, i64 2, !392, i64 8, i64 1, !492, i64 9, i64 1, !492, i64 10, i64 2, !392, i64 12, i64 4, !527, i64 16, i64 4, !527}
!881 = !DILocation(line: 360, column: 33, scope: !612, inlinedAt: !684)
!882 = !DILocation(line: 360, column: 15, scope: !612, inlinedAt: !684)
!883 = !DILocation(line: 360, column: 9, scope: !612, inlinedAt: !684)
!884 = !DILocation(line: 361, column: 1, scope: !612, inlinedAt: !684)
!885 = !DILocation(line: 363, column: 1, scope: !612, inlinedAt: !684)
!886 = !DILocation(line: 378, column: 3, scope: !609)
!887 = !DILocation(line: 381, column: 1, scope: !309)
!888 = distinct !DISubprogram(name: "nat64_ingress", scope: !3, file: !3, line: 389, type: !302, scopeLine: 390, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !889)
!889 = !{!890}
!890 = !DILocalVariable(name: "skb", arg: 1, scope: !888, file: !3, line: 389, type: !147)
!891 = !DILocation(line: 0, scope: !888)
!892 = !DILocation(line: 391, column: 16, scope: !888)
!893 = !DILocation(line: 391, column: 9, scope: !888)
!894 = distinct !DISubprogram(name: "alloc_new_state", scope: !3, file: !3, line: 180, type: !895, scopeLine: 181, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !897)
!895 = !DISubroutineType(types: !896)
!896 = !{!75, !73}
!897 = !{!898, !899, !900, !901, !902, !903, !907, !908, !909}
!898 = !DILocalVariable(name: "src_v6", arg: 1, scope: !894, file: !3, line: 180, type: !73)
!899 = !DILocalVariable(name: "new_v6_state", scope: !894, file: !3, line: 182, type: !76)
!900 = !DILocalVariable(name: "max_v4", scope: !894, file: !3, line: 183, type: !22)
!901 = !DILocalVariable(name: "src_v4", scope: !894, file: !3, line: 184, type: !22)
!902 = !DILocalVariable(name: "i", scope: !894, file: !3, line: 185, type: !69)
!903 = !DILocalVariable(name: "next_v4", scope: !904, file: !3, line: 188, type: !22)
!904 = distinct !DILexicalBlock(scope: !905, file: !3, line: 187, column: 34)
!905 = distinct !DILexicalBlock(scope: !906, file: !3, line: 187, column: 9)
!906 = distinct !DILexicalBlock(scope: !894, file: !3, line: 187, column: 9)
!907 = !DILocalVariable(name: "next_addr", scope: !904, file: !3, line: 188, type: !22)
!908 = !DILabel(scope: !894, name: "err_v4", file: !3, line: 218)
!909 = !DILabel(scope: !894, name: "err", file: !3, line: 220)
!910 = !DILocation(line: 0, scope: !894)
!911 = !DILocation(line: 182, column: 9, scope: !894)
!912 = !DILocation(line: 182, column: 30, scope: !894)
!913 = !DILocation(line: 182, column: 45, scope: !894)
!914 = !DILocation(line: 182, column: 60, scope: !894)
!915 = !{!804, !339, i64 12}
!916 = !DILocation(line: 183, column: 32, scope: !894)
!917 = !DILocation(line: 183, column: 52, scope: !894)
!918 = !DILocation(line: 183, column: 44, scope: !894)
!919 = !DILocation(line: 183, column: 42, scope: !894)
!920 = !DILocation(line: 183, column: 61, scope: !894)
!921 = !DILocation(line: 184, column: 9, scope: !894)
!922 = !DILocation(line: 184, column: 15, scope: !894)
!923 = !DILocation(line: 190, column: 29, scope: !904)
!924 = !DILocation(line: 0, scope: !904)
!925 = !DILocation(line: 191, column: 34, scope: !904)
!926 = !DILocation(line: 191, column: 44, scope: !904)
!927 = !DILocation(line: 193, column: 29, scope: !928)
!928 = distinct !DILexicalBlock(scope: !904, file: !3, line: 193, column: 21)
!929 = !DILocation(line: 193, column: 21, scope: !904)
!930 = !DILocation(line: 169, column: 9, scope: !931, inlinedAt: !937)
!931 = distinct !DISubprogram(name: "reclaim_v4_addr", scope: !3, file: !3, line: 167, type: !932, scopeLine: 168, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !934)
!932 = !DISubroutineType(types: !933)
!933 = !{!22}
!934 = !{!935, !936}
!935 = !DILocalVariable(name: "timeout", scope: !931, file: !3, line: 169, type: !29)
!936 = !DILocalVariable(name: "src_v4", scope: !931, file: !3, line: 170, type: !22)
!937 = distinct !DILocation(line: 194, column: 34, scope: !938)
!938 = distinct !DILexicalBlock(scope: !928, file: !3, line: 193, column: 40)
!939 = !DILocation(line: 169, column: 25, scope: !931, inlinedAt: !937)
!940 = !DILocation(line: 169, column: 53, scope: !931, inlinedAt: !937)
!941 = !{!531, !342, i64 16}
!942 = !DILocation(line: 169, column: 44, scope: !931, inlinedAt: !937)
!943 = !DILocation(line: 0, scope: !931, inlinedAt: !937)
!944 = !DILocation(line: 169, column: 15, scope: !931, inlinedAt: !937)
!945 = !{!342, !342, i64 0}
!946 = !DILocation(line: 170, column: 9, scope: !931, inlinedAt: !937)
!947 = !DILocation(line: 172, column: 13, scope: !948, inlinedAt: !937)
!948 = distinct !DILexicalBlock(scope: !931, file: !3, line: 172, column: 13)
!949 = !DILocation(line: 172, column: 57, scope: !948, inlinedAt: !937)
!950 = !DILocation(line: 172, column: 13, scope: !931, inlinedAt: !937)
!951 = !DILocation(line: 173, column: 24, scope: !948, inlinedAt: !937)
!952 = !DILocation(line: 173, column: 17, scope: !948, inlinedAt: !937)
!953 = !DILocation(line: 175, column: 9, scope: !931, inlinedAt: !937)
!954 = !DILocation(line: 177, column: 16, scope: !931, inlinedAt: !937)
!955 = !DILocation(line: 177, column: 9, scope: !931, inlinedAt: !937)
!956 = !DILocation(line: 178, column: 1, scope: !931, inlinedAt: !937)
!957 = !DILocation(line: 194, column: 32, scope: !938)
!958 = !DILocation(line: 199, column: 49, scope: !959)
!959 = distinct !DILexicalBlock(scope: !904, file: !3, line: 198, column: 21)
!960 = !DILocation(line: 200, column: 59, scope: !959)
!961 = !DILocation(line: 200, column: 49, scope: !959)
!962 = !DILocation(line: 198, column: 21, scope: !959)
!963 = !DILocation(line: 200, column: 64, scope: !959)
!964 = !DILocation(line: 198, column: 21, scope: !904)
!965 = !DILocation(line: 201, column: 32, scope: !966)
!966 = distinct !DILexicalBlock(scope: !959, file: !3, line: 200, column: 78)
!967 = !DILocation(line: 207, column: 14, scope: !968)
!968 = distinct !DILexicalBlock(scope: !894, file: !3, line: 207, column: 13)
!969 = !DILocation(line: 207, column: 13, scope: !894)
!970 = !DILocation(line: 210, column: 30, scope: !894)
!971 = !DILocation(line: 211, column: 48, scope: !972)
!972 = distinct !DILexicalBlock(scope: !894, file: !3, line: 211, column: 13)
!973 = !DILocation(line: 211, column: 13, scope: !972)
!974 = !DILocation(line: 211, column: 13, scope: !894)
!975 = !DILocation(line: 213, column: 13, scope: !976)
!976 = distinct !DILexicalBlock(scope: !894, file: !3, line: 213, column: 13)
!977 = !DILocation(line: 213, column: 13, scope: !894)
!978 = !DILocation(line: 216, column: 16, scope: !894)
!979 = !DILocation(line: 216, column: 9, scope: !894)
!980 = !DILocation(line: 218, column: 1, scope: !894)
!981 = !DILocation(line: 219, column: 9, scope: !894)
!982 = !DILocation(line: 220, column: 1, scope: !894)
!983 = !DILocation(line: 224, column: 9, scope: !894)
!984 = !DILocation(line: 225, column: 9, scope: !894)
!985 = !DILocation(line: 226, column: 1, scope: !894)
!986 = distinct !DISubprogram(name: "check_item", scope: !3, file: !3, line: 147, type: !987, scopeLine: 148, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !991)
!987 = !DISubroutineType(types: !988)
!988 = !{!132, !989, !140, !17, !17}
!989 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !990, size: 64)
!990 = !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_map", file: !3, line: 147, flags: DIFlagFwdDecl)
!991 = !{!992, !993, !994, !995, !996, !997, !998}
!992 = !DILocalVariable(name: "map", arg: 1, scope: !986, file: !3, line: 147, type: !989)
!993 = !DILocalVariable(name: "key", arg: 2, scope: !986, file: !3, line: 147, type: !140)
!994 = !DILocalVariable(name: "value", arg: 3, scope: !986, file: !3, line: 147, type: !17)
!995 = !DILocalVariable(name: "ctx", arg: 4, scope: !986, file: !3, line: 147, type: !17)
!996 = !DILocalVariable(name: "state", scope: !986, file: !3, line: 149, type: !75)
!997 = !DILocalVariable(name: "timeout", scope: !986, file: !3, line: 150, type: !29)
!998 = !DILocalVariable(name: "v4_addr", scope: !999, file: !3, line: 153, type: !22)
!999 = distinct !DILexicalBlock(scope: !1000, file: !3, line: 152, column: 64)
!1000 = distinct !DILexicalBlock(scope: !986, file: !3, line: 152, column: 13)
!1001 = !DILocation(line: 0, scope: !986)
!1002 = !DILocation(line: 150, column: 27, scope: !986)
!1003 = !DILocation(line: 150, column: 25, scope: !986)
!1004 = !DILocation(line: 152, column: 20, scope: !1000)
!1005 = !DILocation(line: 152, column: 30, scope: !1000)
!1006 = !DILocation(line: 152, column: 40, scope: !1000)
!1007 = !DILocation(line: 152, column: 51, scope: !1000)
!1008 = !DILocation(line: 152, column: 44, scope: !1000)
!1009 = !DILocation(line: 152, column: 13, scope: !986)
!1010 = !DILocation(line: 153, column: 17, scope: !999)
!1011 = !DILocation(line: 153, column: 40, scope: !999)
!1012 = !DILocation(line: 0, scope: !999)
!1013 = !DILocation(line: 153, column: 23, scope: !999)
!1014 = !DILocation(line: 154, column: 37, scope: !999)
!1015 = !DILocation(line: 154, column: 17, scope: !999)
!1016 = !DILocation(line: 155, column: 17, scope: !999)
!1017 = !DILocation(line: 156, column: 17, scope: !999)
!1018 = !DILocation(line: 162, column: 9, scope: !1000)
!1019 = !DILocation(line: 165, column: 1, scope: !986)
