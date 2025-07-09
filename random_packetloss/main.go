package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	// コマンドライン引数の処理
	ifaceName := flag.String("iface", "", "ネットワークインタフェース名 (例: eth0)")
	dropRateStr := flag.String("rate", "", "パケットロス率 (0〜100)")
	flag.Parse()

	if *ifaceName == "" || *dropRateStr == "" {
		fmt.Println("Usage: sudo go run main.go -iface <interface> -rate <0-100>")
		os.Exit(1)
	}

	dropRate, err := strconv.Atoi(*dropRateStr)
	if err != nil || dropRate < 0 || dropRate > 100 {
		log.Fatalf("不正なドロップ率: %s", *dropRateStr)
	}

	ifaceIndex, err := getInterfaceIndex(*ifaceName)
	if err != nil {
		log.Fatalf("インタフェース取得失敗: %v", err)
	}

	// BPFプログラムを読み込む
	spec, err := ebpf.LoadCollectionSpec("random_packetloss.bpf.o")
	if err != nil {
		log.Fatalf("BPFオブジェクト読み込み失敗: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("BPFコレクション作成失敗: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["xdp_prog"]
	if prog == nil {
		log.Fatalf("xdp_prog が見つかりません")
	}

	// XDPプログラムをアタッチ
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifaceIndex,
		Flags:     link.XDPGenericMode, // or XDPDriverMode
	})
	if err != nil {
		log.Fatalf("XDPアタッチ失敗: %v", err)
	}
	defer lnk.Close()

	fmt.Printf("XDP プログラムを %s にアタッチしました\n", *ifaceName)

	// マップにドロップ率を書き込む
	dropRateMap := coll.Maps["drop_rate_map"]
	if dropRateMap == nil {
		log.Fatalf("drop_rate_map が見つかりません")
	}

	var key uint32 = 0
	value := uint32(dropRate)
	if err := dropRateMap.Put(key, value); err != nil {
		log.Fatalf("ドロップ率の書き込み失敗: %v", err)
	}

	fmt.Printf("ドロップ率を %d%% に設定しました\n", dropRate)
	fmt.Println("Ctrl+C で終了します")

	select {}
}

func getInterfaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, errors.New("ネットワークインタフェースが見つかりません")
	}
	return iface.Index, nil
}
