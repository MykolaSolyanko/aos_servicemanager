package visclient_test

import (
	"encoding/json"
	"math/rand"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	log "github.com/sirupsen/logrus"
	"gitpct.epam.com/epmd-aepr/aos_servicemanager/visclient"
	"gitpct.epam.com/epmd-aepr/aos_servicemanager/wsserver"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const serverURL = "wss://localhost:8088"

/*******************************************************************************
 * Types
 ******************************************************************************/

type messageProcessor struct {
	sendMessage wsserver.SendMessage
}

/*******************************************************************************
 * Vars
 ******************************************************************************/

var vis *visclient.Client
var server *wsserver.Server
var clientProcessor *messageProcessor

var subscriptionID = "test_subscription"

/*******************************************************************************
 * Init
 ******************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true})
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

/*******************************************************************************
 * Main
 ******************************************************************************/

func TestMain(m *testing.M) {
	rand.Seed(time.Now().UnixNano())

	url, err := url.Parse(serverURL)
	if err != nil {
		log.Fatalf("Can't parse url: %s", err)
	}

	server, err = wsserver.New("TestServer", url.Host, "../wsserver/data/crt.pem", "../wsserver/data/key.pem", newMessageProcessor)
	if err != nil {
		log.Fatalf("Can't create ws server: %s", err)
	}
	defer server.Close()

	vis, err = visclient.New()
	if err != nil {
		log.Fatalf("Error creating VIS client: %s", err)
	}

	if err = vis.Connect(serverURL); err != nil {
		log.Fatalf("Error connecting to VIS server: %s", err)
	}

	ret := m.Run()

	if err = vis.Close(); err != nil {
		log.Fatalf("Error closing VIS: %s", err)
	}

	os.Exit(ret)
}

/*******************************************************************************
 * Tests
 ******************************************************************************/

func TestGetVIN(t *testing.T) {
	vin, err := vis.GetVIN()
	if err != nil {
		t.Fatalf("Error getting VIN: %s", err)
	}

	if vin == "" {
		t.Fatalf("Wrong VIN value: %s", vin)
	}
}

func TestGetUsers(t *testing.T) {
	users, err := vis.GetUsers()
	if err != nil {
		t.Fatalf("Error getting users: %s", err)
	}

	if users == nil {
		t.Fatalf("Wrong users value: %s", users)
	}
}

func TestUsersChanged(t *testing.T) {
	newUsers := []string{generateRandomString(10), generateRandomString(10)}

	message, err := json.Marshal(&visclient.Response{
		Action:         "subscription",
		SubscriptionID: &subscriptionID,
		Value:          map[string][]string{"Attribute.Vehicle.UserIdentification.Users": newUsers}})
	if err != nil {
		t.Fatalf("Error marshal request: %s", err)
	}

	if err := clientProcessor.sendMessage(websocket.TextMessage, message); err != nil {
		t.Fatalf("Error send message: %s", err)
	}

	select {
	case users := <-vis.UsersChangedChannel:
		if len(users) != len(newUsers) {
			t.Errorf("Wrong users len: %d", len(users))
		}

	case <-time.After(100 * time.Millisecond):
		t.Error("Waiting for users changed timeout")
	}
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func generateRandomString(size uint) (result string) {
	letterRunes := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	tmp := make([]rune, size)
	for i := range tmp {
		tmp[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	return string(tmp)
}

func newMessageProcessor(sendMessage wsserver.SendMessage) (processor wsserver.MessageProcessor, err error) {
	clientProcessor = &messageProcessor{sendMessage: sendMessage}

	return clientProcessor, nil
}

func (processor *messageProcessor) ProcessMessage(messageType int, messageIn []byte) (messageOut []byte, err error) {
	var req visclient.Request
	var rsp visclient.Response

	if err = json.Unmarshal(messageIn, &req); err != nil {
		return nil, err
	}

	rsp.Action = req.Action
	rsp.RequestID = &req.RequestID

	switch req.Action {
	case "subscribe":
		rsp.SubscriptionID = &subscriptionID

	case "get":
		switch req.Path {
		case "Attribute.Vehicle.VehicleIdentification.VIN":
			rsp.Value = map[string]string{req.Path: "VIN1234567890"}

		case "Attribute.Vehicle.UserIdentification.Users":
			rsp.Value = map[string][]string{req.Path: []string{"user1", "user2", "user3"}}
		}

	default:
		rsp.Error = &visclient.ErrorInfo{Number: 401, Reason: "", Message: "Unknown action"}
	}

	if messageOut, err = json.Marshal(rsp); err != nil {
		return
	}

	return messageOut, nil
}