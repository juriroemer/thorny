package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"time"
)

// This reads snort output live to be correlated with live packet data read on the interface.
/// Was ultimately not used for thesis as we went into a different direction.

type Snort_Alert struct {
	Timestamp time.Time `json:"timestamp"`
	Pkt_num   int       `json:"pkt_num"`
	Proto     string    `json:"proto"`
	Pkt_gen   string    `json:"pkt_gen"`
	Pkt_len   int       `json:"pkt_len"`
	Dir       string    `json:"dir"`
	Src_ap    string    `json:"src_ap"`
	Dst_ap    string    `json:"dst_ap"`
	Rule      string    `json:"rule"`
	Action    string    `json:"action"`
}

type Snort_Alert_Raw struct {
	Timestamp string `json:"timestamp"`
	Pkt_num   int    `json:"pkt_num"`
	Proto     string `json:"proto"`
	Pkt_gen   string `json:"pkt_gen"`
	Pkt_len   int    `json:"pkt_len"`
	Dir       string `json:"dir"`
	Src_ap    string `json:"src_ap"`
	Dst_ap    string `json:"dst_ap"`
	Rule      string `json:"rule"`
	Action    string `json:"action"`
}

func (a *Snort_Alert) UnmarshalJSON(b []byte) (err error) {
	var sar Snort_Alert_Raw
	if err := json.Unmarshal(b, &sar); err != nil {
		return err
	}

	now := time.Now()
	zone, _ := now.Zone()
	t := sar.Timestamp
	// HACK time.Now().Year() is a minor race condition
	a.Timestamp, err = time.Parse("2006/01/02-15:04:05ZMST", fmt.Sprintf("%d/%sZ%s", time.Now().Year(), t[:14], zone))
	if err != nil {
		panic(err)
	}
	a.Pkt_num = sar.Pkt_num
	a.Proto = sar.Proto
	a.Pkt_gen = sar.Pkt_gen
	a.Pkt_len = sar.Pkt_len
	a.Dir = sar.Dir
	a.Src_ap = sar.Src_ap
	a.Dst_ap = sar.Dst_ap
	a.Rule = sar.Rule
	a.Action = sar.Action
	return
}

func log_snort(rulesPath string) error {
	// Check if file exists at given snort rule path
	if _, err := os.Stat(rulesPath); err != nil {
		return fmt.Errorf("no file for snort rules at %s, please check config", rulesPath)
	}

	slog.Info("Snort rules file found", "path", rulesPath)
	slog.Info("Starting snort")

	cmd := exec.Command("stdbuf", "-oL", "snort", "-q", "-v", "-i", "en0", "-A", "alert_json", "-R", rulesPath)

	// create snort output pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}

	// Start the process before reading from pipes.
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	// Read stdout concurrently
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {

			// Unmarshal Snort alerts
			// TODO send alerts upwards via channel, send them to $somewhere from there
			var alert Snort_Alert
			if err := json.Unmarshal(scanner.Bytes(), &alert); err != nil {
				fmt.Printf("[snort-stdout] %s", scanner.Text())
			}
			fmt.Println(alert)
		}
		if err := scanner.Err(); err != nil {
			fmt.Println("scanner stdout error: ", err)
		}
	}()

	// Read stderr concurrently
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			fmt.Println("[snort-stderr] ", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Println("scanner stderr error: ", err)
		}
	}()

	// Wait for the process to finish
	if err := cmd.Wait(); err != nil {
		log.Fatal(err)
	}
	return nil
}
