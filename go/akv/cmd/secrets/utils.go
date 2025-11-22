package secrets

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/99designs/keyring"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/spf13/cobra"
)

type uriResult struct {
	Uri  string
	Path string
}

func resolveUri(uri string, vault string) (uriResult, error) {
	if uri == "" && vault == "" {
		return uriResult{}, errors.New("either --uri or --vault must be provided")
	}

	if len(uri) == 0 {
		// keyvault url construction
		uri = fmt.Sprintf("https://%s.vault.azure.net", vault)
		return uriResult{
			Uri: uri,
		}, nil
	} else {
		// protocol ommitted vault url
		if strings.Contains(vault, "://") {
			uri = "https://" + uri
		}

		u, err := url.Parse(uri)
		if err != nil {
			return uriResult{}, err
		}

		if u.Scheme == "aks" {
			u.Scheme = "https"
			if !strings.HasSuffix(u.Host, ".vault.azure.net") {
				u.Host = u.Host + ".vault.azure.net"
			}
		}

		path := u.Path
		if len(path) > 0 {
			path = strings.Trim(path, "/")
		}

		u.Path = ""
		uri = u.String()

		return uriResult{
			Uri:  uri,
			Path: path,
		}, nil
	}
}

func toScreamingSnakeCase(input string) string {
	output := ""
	for i, char := range input {
		if char >= 'A' && char <= 'Z' {
			if i > 0 {
				output += "_"
			}
			output += string(char)
		} else if char >= 'a' && char <= 'z' {
			if i > 0 && input[i-1] >= 'A' && input[i-1] <= 'Z' {
				output += "_"
			}
			output += string(char - ('a' - 'A'))
		} else if char >= '0' && char <= '9' {
			output += string(char)
		} else {
			if i > 0 && input[i-1] != '_' {
				output += "_"
			}
		}
	}
	return output
}

func getCredential(cmd *cobra.Command) (azcore.TokenCredential, error) {

	kr, err := openKeyring()

	useKr := err == nil

	identity, _ := cmd.Flags().GetBool("identity")
	clientId, _ := cmd.Flags().GetString("client-id")
	tenantId, _ := cmd.Flags().GetString("tenant-id")
	clientSecret, _ := cmd.Flags().GetString("client-secret")
	servicePrincipal, _ := cmd.Flags().GetBool("service-principal")
	cli, _ := cmd.Flags().GetBool("use-cli")
	deviceCode, _ := cmd.Flags().GetBool("use-device-code")

	vault, _ := cmd.Flags().GetString("vault")
	uri, err := url.Parse(vault)
	name := ""
	if err != nil {
		name = vault
	} else {
		hostParts := strings.Split(uri.Host, ".")
		if len(hostParts) > 0 {
			name = hostParts[0]
		}
	}

	clientIdKey := fmt.Sprintf("akv:%s:%s", name, "client-id")
	clientSecretKey := fmt.Sprintf("akv:%s:%s", name, "client-secret")
	tenantIdKey := fmt.Sprintf("akv:%s:%s", name, "tenant-id")
	managedIdKey := fmt.Sprintf("akv:%s:%s", name, "managed-identity")

	if cli {
		return azidentity.NewAzureCLICredential(nil)
	}

	if deviceCode {
		return azidentity.NewDeviceCodeCredential(nil)
	}

	if identity {
		if clientId != "" {
			azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
				ID: azidentity.ClientID(clientId),
			})
		}

		if useKr {
			item, err := kr.Get(managedIdKey)
			if err != nil {
				item2, err2 := kr.Get("akv:managed-identity")
				if err2 == nil {
					clientId := string(item2.Data)
					return azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
						ID: azidentity.ClientID(clientId),
					})
				}
			}

			if err == nil {
				clientId := string(item.Data)
				return azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
					ID: azidentity.ClientID(clientId),
				})
			}
		}

		return azidentity.NewManagedIdentityCredential(nil)
	}

	if servicePrincipal {

		if useKr {
			if clientSecret == "" {
				item, err := kr.Get(clientIdKey)
				if err == nil {
					clientSecret = string(item.Data)
				}
			}

			if clientId == "" {
				item, err := kr.Get(clientSecretKey)
				if err == nil {
					clientId = string(item.Data)
				}
			}

			if tenantId == "" {
				item, err := kr.Get(tenantIdKey)
				if err == nil {
					tenantId = string(item.Data)
				}
			}
		}

		if clientId == "" {
			return nil, errors.New("client-id must not be null when --service-principal is used")
		}

		if clientSecret == "" {
			return nil, errors.New("client-secret must not be null when --service-principal is used")
		}

		if tenantId == "" {
			return nil, errors.New("tenant-id must not be null when --service-principal is used")
		}

		return azidentity.NewClientSecretCredential(tenantId, clientId, clientSecret, nil)
	}

	return azidentity.NewDefaultAzureCredential(nil)
}

func openKeyring() (keyring.Keyring, error) {
	kr, err := keyring.Open(keyring.Config{
		ServiceName:             "login",
		LibSecretCollectionName: "login",
		KeychainName:            "login",
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,
			keyring.WinCredBackend,
			keyring.SecretServiceBackend,
		},
	})
	return kr, err
}
