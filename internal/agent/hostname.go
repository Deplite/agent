package agent

import "os"

func hostnameImpl() (string, error) { return os.Hostname() }
