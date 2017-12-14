// Copyright 2017 Intel Corp.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/golang/glog"
)

const defaultCNIDir = "/var/lib/cni/vhostuser"

// VhostConf type defines a vhost-user configuration
type VhostConf struct {
	VhostPortName string `json:"vhostportname"` // Vhost Port name
	VhostPortMac  string `json:"vhostmac"`      // Vhost port MAC address
	Ifname        string `json:"ifname"`        // Interface name
	IfMac         string `json:"ifmac"`         // Interface Mac address
	IfIP          string `json:"ifip"`          // Interface IP Address
	VhostTool     string `json:"vhost_tool"`    // Scripts for configuration
}

// NetConf type defines a network interfaces configuration
type NetConf struct {
	types.NetConf
	VhostConf VhostConf `json:"vhost,omitempty"`
	If0name   string    `json:"if0name"`
	CNIDir    string    `json:"cniDir"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

// ExecCommand Execute shell commands and return the output.
func ExecCommand(cmd string, args []string) ([]byte, error) {
	return exec.Command(cmd, args...).Output()
}

func loadConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		glog.Errorf("failed to load netconf: %v", err)
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	if n.CNIDir == "" {
		n.CNIDir = defaultCNIDir
	}

	return n, nil
}

// saveVhostConf Save the rendered netconf for cmdDel
func saveVhostConf(conf *NetConf, containerID string) error {
	fileName := fmt.Sprintf("%s-%s.json", containerID[:12], conf.If0name)

	vhostConfBytes, err := json.Marshal(conf.VhostConf)
	if err != nil {
		glog.Errorf("saveVhostConf: error serializing delegate netconf: %v", err)
		return fmt.Errorf("error serializing delegate netconf: %v", err)
	}

	sockDir := filepath.Join(conf.CNIDir, containerID)
	path := filepath.Join(sockDir, fileName)

	return ioutil.WriteFile(path, vhostConfBytes, 0644)

}

func (vc *VhostConf) loadVhostConf(conf *NetConf, containerID string) error {
	fileName := fmt.Sprintf("%s-%s.json", containerID[:12], conf.If0name)
	sockDir := filepath.Join(conf.CNIDir, containerID)
	path := filepath.Join(sockDir, fileName)

	data, err := ioutil.ReadFile(path)
	if err != nil {
		glog.Errorf("loadVhostConf: Failed to read config: %v", err)
		return fmt.Errorf("failed to read config: %v", err)
	}

	if err = json.Unmarshal(data, vc); err != nil {
		glog.Errorf("loadVhostConf: Failed to parse VhostConf: %v", err)
		return fmt.Errorf("failed to parse VhostConf: %v", err)
	}

	return nil
}

func createVhostPort(conf *NetConf, containerID string, netns ns.NetNS) error {
	s := []string{containerID[:12], conf.If0name}
	sockRef := strings.Join(s, "-")

	sockDir := filepath.Join(conf.CNIDir, containerID)
	if _, err := os.Stat(sockDir); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(sockDir, 0700); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	sockPath := filepath.Join(sockDir, sockRef)

	// vppctl create vhost socket <socket-path> server
	cmd := conf.VhostConf.VhostTool
	args := []string{"create", sockPath}
	output, err := ExecCommand(cmd, args)
	if err != nil {
		glog.Errorf("Error createVhostPort: [%v] [%v] [%v]",
			cmd, args, err)
		return err
	}

	vhostPortName := strings.Replace(string(output), "\n", "", -1)

	// vppctl getmac <vhost interface name>
	args = []string{"getmac", vhostPortName}
	if output, err := ExecCommand(cmd, args); err != nil {
		glog.Errorf("Error EndPointCreate: [%v] [%v] [%v]",
			cmd, args, err)
	} else {
		conf.VhostConf.VhostPortMac = strings.Replace(string(output), "\n", "", -1)
	}

	conf.VhostConf.VhostPortName = vhostPortName
	conf.VhostConf.Ifname = conf.If0name
	conf.VhostConf.IfMac = generateRandomMacAddress()

	/* Setup a dummy interface corresponding to the vhost-user network.
	 * Runtime's like Clear Containers will see this dummy interface as
	 * a hint that there's a vhost-user socket available to pass to the VM
	 */

	err = netns.Do(func(_ ns.NetNS) error {
		cmd := "ip"
		args := []string{"link", "add", conf.VhostConf.IfIP, "type", "dummy"}
		if err := exec.Command(cmd, args...).Run(); err != nil {
			return fmt.Errorf("Error EndPointCreate: [%v] [%v] [%v]",
				cmd, args, err)
		}
		return nil
	})
	if err != nil {
		glog.Errorf("Failed to create link in netns: %v", err)
		return err
	}
	return saveVhostConf(conf, containerID)
}

func destroyVhostPort(conf *NetConf, containerID string, nsID string) error {
	vc := &VhostConf{}
	if err := vc.loadVhostConf(conf, containerID); err != nil {
		return err
	}

	//vppctl delete vhost-user VirtualEthernet0/0/0
	args := []string{"delete", vc.VhostPortName}
	if _, err := ExecCommand(conf.VhostConf.VhostTool, args); err != nil {
		glog.Errorf("Error destroyVhostPort: [%v] [%v] [%v]",
			conf.VhostConf.VhostTool, args, err)
		return err
	}

	//delete dummy port from inside the namespace. The name of it is
	// the actual device's IP:
	if nsID != "" {
		netns, err := ns.GetNS(nsID)
		if err != nil {
			glog.Errorf("failed to to open netns %q, @v", nsID, err)
			return fmt.Errorf("failed to open netns: %q, %v", nsID, err)
		}
		defer netns.Close()

		err = netns.Do(func(_ ns.NetNS) error {
			cmd := "ip"
			args = []string{"link", "del", vc.IfIP}
			if err := exec.Command(cmd, args...).Run(); err != nil {
				return fmt.Errorf("Error destroyVhostPort: [%v] [%v] [%v]",
					cmd, args, err)
			}
			return nil
		})
		if err != nil {
			glog.Errorf("failed to delete link in ns: %v", err)
			return err
		}
	}
	path := filepath.Join(conf.CNIDir, containerID)
	return os.RemoveAll(path)
}

const netConfigTemplate = `{
	"ipAddr": "%s/32",
	"macAddr": "%s",
	"gateway": "169.254.1.1",
	"gwMac": "%s"
}
`

func generateRandomMacAddress() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}

	// Set the local bit and make sure not MC address
	macAddr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		(buf[0]|0x2)&0xfe, buf[1], buf[2],
		buf[3], buf[4], buf[5])
	return macAddr
}

// SetupContainerNetwork writes the configuration to file
func SetupContainerNetwork(conf *NetConf, containerID, containerIP string) {
	args := []string{"config", conf.VhostConf.VhostPortName, containerIP, conf.VhostConf.IfMac}
	ExecCommand(conf.VhostConf.VhostTool, args)

	// Write the configuration to file
	config := fmt.Sprintf(netConfigTemplate, containerIP, conf.VhostConf.IfMac, conf.VhostConf.VhostPortMac)
	fileName := fmt.Sprintf("%s-%s-ip4.conf", containerID[:12], conf.If0name)
	sockDir := filepath.Join(conf.CNIDir, containerID)
	configFile := filepath.Join(sockDir, fileName)
	ioutil.WriteFile(configFile, []byte(config), 0644)
}

func cmdAdd(args *skel.CmdArgs) error {
	var result *types.Result
	var n *NetConf

	n, err := loadConf(args.StdinData)
	if err != nil {
		return result.Print()
	}

	// run the IPAM plugin and get back the config to apply
	result, err = ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to set up IPAM: %v", err)
	}
	if result.IP4 == nil {
		return errors.New("IPAM plugin returned missing IPv4 config")
	}

	n.VhostConf.IfIP = result.IP4.IP.IP.String()

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	createVhostPort(n, args.ContainerID, netns)

	containerIP := result.IP4.IP.IP.String()
	SetupContainerNetwork(n, args.ContainerID, containerIP)

	return result.Print()
}

func cmdDel(args *skel.CmdArgs) error {

	n, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	if err = destroyVhostPort(n, args.ContainerID, args.Netns); err != nil {
		return err
	}

	return ipam.ExecDel(n.IPAM.Type, args.StdinData)
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel)
}
