/*
Copyright 2023 AmidaWare Inc.

Licensed under the Tactical RMM License Version 1.0 (the "License").
You may only use the Licensed Software in accordance with the License.
A copy of the License is available at:

https://license.tacticalrmm.com

*/

package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/osquery/osquery-go"
)

// OSQueryClient wraps the osquery-go client for interacting with osqueryd
type OSQueryClient struct {
	client    *osquery.ExtensionManagerClient
	socket    string
	timeout   time.Duration
	connected bool
	agent     *Agent
}

// NewOSQueryClient creates a new OSQuery client
// socketPath: path to the osqueryd extension socket (e.g., /var/tacticalosquery/osquery.em)
func NewOSQueryClient(socketPath string, agent *Agent) *OSQueryClient {
	return &OSQueryClient{
		socket:    socketPath,
		timeout:   10 * time.Second,
		connected: false,
		agent:     agent,
	}
}

// Connect establishes a connection to the osqueryd daemon
func (c *OSQueryClient) Connect() error {
	client, err := osquery.NewClient(c.socket, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to osquery at %s: %w", c.socket, err)
	}

	c.client = client
	c.connected = true
	c.agent.Logger.Infof("Connected to OSQuery daemon at %s", c.socket)
	return nil
}

// Disconnect closes the connection to osqueryd
func (c *OSQueryClient) Disconnect() error {
	if c.client != nil {
		c.client.Close()
		c.connected = false
		c.agent.Logger.Debug("Disconnected from OSQuery daemon")
	}
	return nil
}

// Query executes a SQL query against osqueryd and returns the results
func (c *OSQueryClient) Query(sql string) ([]map[string]string, error) {
	// Connect if not already connected
	if !c.connected {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}

	// Execute query with timeout
	// Note: osquery-go doesn't currently support context, but we keep this for future use
	_, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	resp, err := c.client.Query(sql)
	if err != nil {
		// Try to reconnect once
		c.agent.Logger.Warn("Query failed, attempting reconnect...")
		c.connected = false

		if err := c.Connect(); err != nil {
			return nil, fmt.Errorf("reconnect failed: %w", err)
		}

		// Retry query
		resp, err = c.client.Query(sql)
		if err != nil {
			return nil, fmt.Errorf("query execution failed: %w", err)
		}
	}

	// Check response status
	if resp.Status.Code != 0 {
		return nil, fmt.Errorf("query error (code %d): %s", resp.Status.Code, resp.Status.Message)
	}

	c.agent.Logger.Debugf("Query executed successfully, returned %d rows", len(resp.Response))
	return resp.Response, nil
}

// Ping tests the connection to osqueryd by executing a simple query
func (c *OSQueryClient) Ping() error {
	_, err := c.Query("SELECT 1")
	return err
}
