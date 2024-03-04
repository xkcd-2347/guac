package helpers

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/Khan/genqlient/graphql"
	"github.com/spf13/viper"
)

func GetGqlClient(graphqlEndpoint string) (graphql.Client, error) {
	httpClient := http.Client{}
	certFile := viper.GetString("gql-tls-root-ca")
	insecure := viper.GetBool("gql-tls-insecure")
	if certFile != "" {
		caCert, err := os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("unable to read root certificate: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		httpClient = http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:            caCertPool,
					InsecureSkipVerify: insecure,
				},
			},
		}
	}

	return graphql.NewClient(graphqlEndpoint, &httpClient), nil
}
