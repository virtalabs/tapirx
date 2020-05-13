package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/eclipse/paho.mqtt.golang"
)

const (
	cmqttClientId = "tapirx"
	cDevType      = cmqttClientId
	cMsgType      = "medsniff"
)

type MQTTWriter struct {
	enabled bool
	client  mqtt.Client
	token   mqtt.Token
	topic   string
}

type mqttAsset struct {
	LastSeenInt int64  `json:"timelastseen"`
	Address     string `json:"addr"`
	IPAddr      string `json:"ip_addr"`
	Port        int    `json:"port"`
	Provenance  string `json:"proto"`
	Identifier  string `json:"model"`
}

type mqttPayload struct {
	Timestamp int64       `json:"timestamp"`
	DevType   string      `json:"dev_type"`
	MsgType   string      `json:"msg_type"`
	Assets    []mqttAsset `json:"devices"`
}

func NewMQTTWriter(uri string) (*MQTTWriter, error) {
	if uri == "" {
		return nil, nil
	}

	mqttUri, err := url.Parse(uri)
	if err != nil {
		logger.Printf("Unable to parse mqtt url: %s error: %s", uri, err)
		return nil, err
	}

	opts := createClientOptions(uri)
	client := mqtt.NewClient(opts)
	token := client.Connect()
	if !token.WaitTimeout(time.Second * 10) {
		fmt.Printf("MQTT Connect failed")
	}
	if token.Error() != nil {
		logger.Printf("Unable to connect MQTT at : %s err:%s\n", uri, token.Error())
		return nil, token.Error()
	}

	writer := &MQTTWriter{
		enabled: false,
	}
	writer.client = client
	writer.token = token
	writer.topic = mqttUri.Path
	writer.enabled = true
	return writer, nil
}

func createClientOptions(uri string) *mqtt.ClientOptions {
	mqttUri, err := url.Parse(uri)
	if err != nil {
		return nil
	}
	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("tcp://%s", mqttUri.Host))
	opts.SetClientID(cmqttClientId)
	opts.SetAutoReconnect(true)
	return opts
}

func (mq *MQTTWriter) Close() {
	if mq.enabled {
		mq.client.Disconnect(3)
	}
	mq.enabled = false
}

func (mq *MQTTWriter) Enabled() bool {
	return mq.enabled
}

func (mq *MQTTWriter) Publish(asset *Asset) error {
	if !mq.Enabled() {
		return nil
	}

	payload := mqttPayload{
		Timestamp: time.Now().Unix(),
		DevType:   cDevType,
		MsgType:   cMsgType,
		Assets:    make([]mqttAsset, 0),
	}

	mqAsset := mqttAsset{
		LastSeenInt: asset.LastSeen.Unix(),
		Address:     asset.MACAddress,
		IPAddr:      asset.IPv4Address,
		Identifier:  asset.Identifier,
		Provenance:  asset.Provenance,
		Port:        -1,
	}
	if mqAsset.IPAddr == "" {
		mqAsset.IPAddr = asset.IPv6Address
	}
	if asset.ListensOnPort != "" {
		mqAsset.Port, _ = strconv.Atoi(asset.ListensOnPort)
	}
	payload.Assets = append(payload.Assets, mqAsset)

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	mq.client.Publish(mq.topic, 0, false, jsonBytes)
	return nil
}
