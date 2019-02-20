package login

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/command/flags"
	"github.com/hashicorp/consul/lib/file"
	"github.com/mitchellh/cli"
)

func New(ui cli.Ui) *cmd {
	c := &cmd{UI: ui}
	c.init()
	return c
}

type cmd struct {
	UI    cli.Ui
	flags *flag.FlagSet
	http  *flags.HTTPFlags
	help  string

	shutdownCh <-chan struct{}

	idpToken string

	// flags
	idpType       string
	idpName       string
	idpTokenPath  string
	tokenSinkFile string
	meta          map[string]string
}

func (c *cmd) init() {
	c.flags = flag.NewFlagSet("", flag.ContinueOnError)

	c.flags.StringVar(&c.idpType, "idp-type", "",
		"The type of the identity provider to login to.")

	c.flags.StringVar(&c.idpName, "idp-name", "",
		"Name of the identity provider to login to.")

	c.flags.StringVar(&c.idpTokenPath, "idp-token-path", "",
		"Path to a file containing a secret bearer token to use with this identity provider.")

	c.flags.StringVar(&c.tokenSinkFile, "token-sink-file", "",
		"The most recent token's SecretID is kept up to date in this file.")

	c.flags.Var((*flags.FlagMapValue)(&c.meta), "meta",
		"Metadata to set on the token, formatted as key=value. This flag "+
			"may be specified multiple times to set multiple meta fields.")

	c.http = &flags.HTTPFlags{}
	flags.Merge(c.flags, c.http.ClientFlags())
	flags.Merge(c.flags, c.http.ServerFlags())
	c.help = flags.Usage(help, c.flags)
}

func (c *cmd) Run(args []string) int {
	if err := c.flags.Parse(args); err != nil {
		return 1
	}
	if len(c.flags.Args()) > 0 {
		c.UI.Error(fmt.Sprintf("Should have no non-flag arguments."))
		return 1
	}

	if c.idpType == "" {
		c.UI.Error(fmt.Sprintf("-idp-type is required"))
		return 1
	}
	if c.idpName == "" {
		c.UI.Error(fmt.Sprintf("-idp-name is required"))
		return 1
	}
	if c.tokenSinkFile == "" {
		c.UI.Error(fmt.Sprintf("-token-sink-file is required"))
		return 1
	}

	switch c.idpType {
	case "kubernetes":
		if c.idpTokenPath == "" {
			c.UI.Error(fmt.Sprintf("-idp-token-path is required"))
			return 1
		}

		data, err := ioutil.ReadFile(c.idpTokenPath)
		if err != nil {
			c.UI.Error(err.Error())
			return 1
		}
		c.idpToken = strings.TrimSpace(string(data))

		if c.idpToken == "" {
			c.UI.Error(fmt.Sprintf("No idp token found in %s", c.idpTokenPath))
			return 1
		}
	default:
		c.UI.Error(fmt.Sprintf("-idp-type is not valid"))
		return 1
	}

	// Ensure that we don't try to use a token when performing a login
	// operation.
	c.http.SetToken("")
	c.http.SetTokenFile("")

	client, err := c.http.APIClient()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error connecting to Consul agent: %s", err))
		return 1
	}

	// Do the login.
	req := &api.ACLLoginParams{
		IDPType:  c.idpType,
		IDPName:  c.idpName,
		IDPToken: c.idpToken,
		Meta:     c.meta,
	}
	tok, _, err := client.ACL().Login(req, nil)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error logging in: %s", err))
		return 1
	}

	if err := c.writeToSink(tok); err != nil {
		c.UI.Error(fmt.Sprintf("Error writing token to file sink: %s", err))
		return 1
	}

	return 0
}

func (c *cmd) writeToSink(tok *api.ACLToken) error {
	payload := []byte(tok.SecretID)
	return file.WriteAtomicWithPerms(c.tokenSinkFile, payload, 0600)
}

func (c *cmd) Synopsis() string {
	return synopsis
}

func (c *cmd) Help() string {
	return flags.Usage(c.help, nil)
}

const synopsis = "Login to Consul using an Identity Provider"

const help = `
Usage: consul acl login [options]

  The login command will exchange the provided third party credentials with the
  requested identity provider for a newly minted Consul ACL Token. The companion
  command 'consul acl logout' should be used to destroy any tokens created this
  way to avoid a resource leak.
`
