package vault

import (
	"fmt"
	"log"
	"os"

	vapi "github.com/hashicorp/vault/api"
)

type Renew struct {
	Logger  *log.Logger
	renewer *vapi.Renewer
}

func NewRenew(client *vapi.Client, secret *vapi.Secret) (*Renew, error) {
	renewer, err := client.NewRenewer(&vapi.RenewerInput{
		Secret: secret,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Renewer: %v", err)
	}
	return &Renew{
		Logger:  log.New(os.Stderr, "", log.LstdFlags),
		renewer: renewer,
	}, nil
}

func (r *Renew) Run() {
	go r.renewer.Renew()
	defer r.renewer.Stop()

	for {
		select {
		case err := <-r.renewer.DoneCh():
			if err != nil {
				r.Logger.Printf("failed to renew: %v\n", err.Error())
			}
		case renewal := <-r.renewer.RenewCh():
			r.Logger.Printf("Successfully renewed: request_id=%v\n", renewal.Secret.RequestID)
		}
	}
}
