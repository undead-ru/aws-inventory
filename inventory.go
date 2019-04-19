package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/organizations"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const positiveResults = true

var (
	awsAccessKeyID        string
	awsSecretAccessKey    string
	mainAccountID         string
	awsRegion             string
	awsRoleName           string
	sshKeyFileName        string
	sshUserName           string
	accountsToSkip        string
	isDebug               bool
)

type awsAccount struct {
	Arn    string
	Name   string
	Status string
}

type awsInstance struct {
	ID        string
	PrivateIP string
	PublicIP  string
	Type      string
	AZ        string
	Name      string
}

func getSession() *session.Session {

	if awsAccessKeyID == "" {
		awsAccessKeyID = os.Getenv("AWS_ACCESS_KEY_ID")
	}

	if awsSecretAccessKey == "" {
		awsSecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}

	awsConf := aws.Config{Credentials: credentials.NewStaticCredentials(awsAccessKeyID, awsSecretAccessKey, ""), Region: &awsRegion}
	sess, err := session.NewSessionWithOptions(session.Options{Config: awsConf})
	if err != nil {
		fmt.Println("failed to create AWS session,", err)
		os.Exit(1)
	}

	svc := sts.New(sess)
	input := &sts.GetCallerIdentityInput{}
	result, err := svc.GetCallerIdentity(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
		os.Exit(1)
	}

	mainAccountID = *result.Account

	return sess
}

func getRegions(sess *session.Session) []string {

	var awsRegions []string
	ec2client := ec2.New(sess)
	regions, err := ec2client.DescribeRegions(&ec2.DescribeRegionsInput{})

	if err != nil {
		fmt.Println("Can't describe regions:", err)
		os.Exit(1)
	}

	for _, region := range regions.Regions {
		awsRegions = append(awsRegions, *region.RegionName)
	}

	return awsRegions
}

func getSubaccounts(sess *session.Session) (map[string]awsAccount, int) {

	var nextToken string
	var i, accountsCount int

	accountsList := make(map[string]awsAccount)

	svc := organizations.New(sess, &aws.Config{Region: aws.String(awsRegion)})

	input := &organizations.ListAccountsInput{}

	for {
		if i > 0 {
			input = &organizations.ListAccountsInput{NextToken: &nextToken}
		}

		result, err := svc.ListAccounts(input)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case organizations.ErrCodeAccessDeniedException:
					fmt.Println(organizations.ErrCodeAccessDeniedException, aerr.Error())
				case organizations.ErrCodeAWSOrganizationsNotInUseException:
					fmt.Println(organizations.ErrCodeAWSOrganizationsNotInUseException, aerr.Error())
				case organizations.ErrCodeInvalidInputException:
					fmt.Println(organizations.ErrCodeInvalidInputException, aerr.Error())
				case organizations.ErrCodeServiceException:
					fmt.Println(organizations.ErrCodeServiceException, aerr.Error())
				case organizations.ErrCodeTooManyRequestsException:
					fmt.Println(organizations.ErrCodeTooManyRequestsException, aerr.Error())
				default:
					fmt.Println(aerr.Error())
				}
			} else {
				fmt.Println(err.Error())
			}
			return accountsList, accountsCount
		}

		for _, x := range result.Accounts {
			accountsList[*x.Id] = awsAccount{Arn: *x.Arn, Name: *x.Name, Status: *x.Status}
			accountsCount++
		}

		if result.NextToken != nil {
			nextToken = *result.NextToken
			i++
		} else {
			break
		}
	}

	return accountsList, accountsCount
}

func getHosts(sess *session.Session, accountID string) ([]awsInstance, int) {

	for _, i := range strings.Split(accountsToSkip, ",") {
		if i == accountID {
			return []awsInstance{}, 0
		}
	}

	var hostSlice []awsInstance
	var creds *credentials.Credentials
	var hostsCount int

	awsRegions := getRegions(sess)
	for _, reg := range awsRegions {
		var svc *ec2.EC2

		if accountID != mainAccountID {
			arn := fmt.Sprintf("arn:aws:iam::%v:role/%v", accountID, awsRoleName)
			creds = stscreds.NewCredentials(sess, arn)
			config := aws.NewConfig().WithCredentials(creds).WithRegion(reg).WithMaxRetries(10)
			svc = ec2.New(sess, config)
		} else {
			config := aws.NewConfig().WithRegion(reg).WithMaxRetries(10)
			svc = ec2.New(sess, config)
		}

		var nextToken string
		var i int

		input := &ec2.DescribeInstancesInput{
			Filters: []*ec2.Filter{
				{
					Name: aws.String("instance-state-name"),
					Values: []*string{
						aws.String("running"),
					},
				},
			},
		}

		for {
			if i > 0 {
				input.NextToken = &nextToken
			}

			result, err := svc.DescribeInstances(input)
			if err != nil {
				if aerr, ok := err.(awserr.Error); ok {
					switch aerr.Code() {
					default:
						fmt.Println("Account:", accountID, aerr.Error())
					}
				} else {
					fmt.Println("Account:", accountID, err.Error())
				}
				return hostSlice, 0
			}

			for _, x := range result.Reservations {
				for _, z := range x.Instances {
					tagName := "NO_NAME"
					var publicIP, privateIP string
					for _, tag := range z.Tags {
						if *tag.Key == "Name" {
							tagName = *tag.Value
							continue
						}
					}

					if z.PublicIpAddress != nil {
						publicIP = *z.PublicIpAddress
					}

					if z.PrivateIpAddress != nil {
						privateIP = *z.PrivateIpAddress
					}

					hostSlice = append(hostSlice, awsInstance{
						ID:        *z.InstanceId,
						PrivateIP: privateIP,
						PublicIP:  publicIP,
						Type:      *z.InstanceType,
						AZ:        *z.Placement.AvailabilityZone,
						Name:      tagName,
					})

					hostsCount++
				}
			}

			if result.NextToken != nil {
				nextToken = *result.NextToken
				i++
			} else {
				break
			}
		}
	}

	return hostSlice, hostsCount
}

func checkSSHKey() ssh.Signer {

	var signer ssh.Signer

	key, err := ioutil.ReadFile(sshKeyFileName)
	if err != nil {
		fmt.Println("unable to read private key:", err)
		os.Exit(1)
	}

	signer, err = ssh.ParsePrivateKey(key)
	if fmt.Sprintf("%v", err) == "ssh: cannot decode encrypted private keys" {
		fmt.Print("Enter passphrase for ", sshKeyFileName+": ")
		bytePassword, _ := terminal.ReadPassword(0)
		fmt.Println()
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, bytePassword)
		if err != nil {
			fmt.Println("unable to parse private keys with passphrase:", err)
			os.Exit(1)
		}
	} else if err != nil {
		fmt.Println("unable to parse private key:", err)
		os.Exit(1)
	}

	return signer
}

func checkSSH(signer ssh.Signer, ip string) string {

	for _, userName := range strings.Split(sshUserName, ",") {

		config := &ssh.ClientConfig{
			Timeout: 10 * time.Second,
			User:    userName,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signer),
			},
		}
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()

		if isDebug {
			fmt.Println("Trying to connect to", ip, "as", userName)
		}

		client, err := ssh.Dial("tcp", ip+":22", config)
		if err == nil {
			client.Close()
			return userName
		} 
		
		if isDebug {
			fmt.Println("SSH error:", err)
		}
	}

	return ""
}

func accountsList() {

	sess := getSession()

	accountsList, accountsCount := getSubaccounts(sess)
	if accountsCount == 0 {
		return
	}
	fmt.Println("ID \t\tSTATUS      \tNAME")
	fmt.Println(strings.Repeat("-", 60))
	for z, x := range accountsList {
		if z == mainAccountID {
			x.Status = x.Status + " / MAIN"
		}
		fmt.Printf("%s\t%-13s\t%s\n", z, x.Status, x.Name)
	}

	fmt.Println("Total accounts:", accountsCount)
}

func accountsCheck() {

	sess := getSession()

	accountsList, accountsCount := getSubaccounts(sess)
	if accountsCount == 0 {
		return
	}

	fmt.Println("ID \t\tSTATUS      \tNAME                     \tACCESS TO EC2")
	fmt.Println(strings.Repeat("-", 77))
	for z, x := range accountsList {
		if z == mainAccountID {
			x.Status = x.Status + " / MAIN"
		}

		fmt.Printf("%s\t%-13s\t%-25s", z, x.Status, x.Name)

		if z == mainAccountID {
			fmt.Println()
			continue
		}

		arn := fmt.Sprintf("arn:aws:iam::%v:role/%v", z, awsRoleName)
		creds := stscreds.NewCredentials(sess, arn)
		config := aws.NewConfig().WithCredentials(creds).WithRegion(awsRegion).WithMaxRetries(10)
		svc := ec2.New(sess, config)

		input := &ec2.DescribeInstancesInput{
			Filters: []*ec2.Filter{
				{
					Name: aws.String("instance-state-name"),
					Values: []*string{
						aws.String("running"),
					},
				},
			},
		}

		_, err := svc.DescribeInstances(input)
		if err != nil {
			fmt.Print("\tAccess Denied")
		}

		fmt.Println()
	}

	fmt.Println("Total accounts:", accountsCount)
}

func hostsList(accountID string) {

	var totalHosts, addHosts int
	var accountsCount int
	accountsList := make(map[string]awsAccount)

	sess := getSession()

	if accountID == strings.ToLower("all") {
		accountsList, accountsCount = getSubaccounts(sess)
	} else {
		accountsList[accountID] = awsAccount{Name: "Name Undefined"}
		accountsCount = 1
	}

	for awsAccountID, acc := range accountsList {
		if acc.Status == "SUSPENDED" {
			continue
		}

		var hostSlice []awsInstance

		fmt.Println("Getting list of hosts from account:", awsAccountID, "("+acc.Name+")\n")
		hostSlice, addHosts = getHosts(sess, awsAccountID)
		if addHosts != 0 {

			totalHosts += addHosts
			for _, z := range hostSlice {
				fmt.Println(z.ID, "\t", z.PrivateIP, "\t", z.PublicIP, "\t", z.Type, "\t", z.AZ, "\t", z.Name)
			}
		}

		fmt.Println()
		fmt.Println(addHosts, "hosts on", awsAccountID, "("+acc.Name+")")
		fmt.Println(strings.Repeat("-", 78))
	}

	fmt.Println("Total:", totalHosts, "hosts in", accountsCount, "account(s)")
}

func hostsCheck(accountID string) {

	var totalHosts, addHosts int
	accountsList := make(map[string]awsAccount)
	var accountsCount int

	signer := checkSSHKey()
	sess := getSession()

	if accountID == strings.ToLower("all") {
		accountsList, accountsCount = getSubaccounts(sess)
	} else {
		accountsList[accountID] = awsAccount{Name: "Undefined"}
		accountsCount = 1
	}

	for awsAccountID, acc := range accountsList {
		if acc.Status == "SUSPENDED" {
			continue
		}

		var hostSlice []awsInstance

		hostSlice, addHosts = getHosts(sess, awsAccountID)
		if addHosts == 0 {
			continue
		}

		totalHosts += addHosts
		for _, z := range hostSlice {
			if z.PrivateIP != "" {
				goodUser := checkSSH(signer, z.PrivateIP)
				if goodUser != "" {
					if positiveResults {
						fmt.Println("+\tPRIVATE", goodUser+"@"+z.PrivateIP+"\t"+awsAccountID+"\t"+z.ID+"\t"+z.Type+"\t"+z.AZ+"\t"+z.Name)
					}
					continue
				}
			}

			if z.PublicIP != "" {
				goodUser := checkSSH(signer, z.PublicIP)
				if goodUser != "" {
					if positiveResults {
						fmt.Println("+\tPUBLIC ", goodUser+"@"+z.PublicIP+"\t"+awsAccountID+"\t"+z.ID+"\t"+z.Type+"\t"+z.AZ+"\t"+z.Name)
					}
					continue
				}
				z.PublicIP = "/" + z.PublicIP
			}

			fmt.Println("-\tPRI/PUB", z.PrivateIP+z.PublicIP+"\t"+awsAccountID+"\t"+z.ID+"\t"+z.Type+"\t"+z.AZ+"\t"+z.Name)
		}
	}

	fmt.Println("Total:", totalHosts, "hosts in", accountsCount, "account(s)")
}

func main() {
	
	programName := filepath.Base(os.Args[0])

	var cmdAccountsList = &cobra.Command{
		Use:   "accounts-list",
		Short: "Shows list of all subaccounts in account",
		Long:  ``,
		Args:  cobra.MinimumNArgs(0),
		Example: "  "+programName+" accounts-list",
		Run: func(cmd *cobra.Command, args []string) {
			accountsList()
		},
	}

	var cmdAccountsCheck = &cobra.Command{
		Use:   "accounts-check",
		Short: "Check access to all subaccounts in account",
		Long:  ``,
		Args:  cobra.MinimumNArgs(0),
		Example: "  "+programName+" accounts-check --role MySwitchRole",
		Run: func(cmd *cobra.Command, args []string) {
			accountsCheck()
		},
	}

	var cmdHostsList = &cobra.Command{
		Use:   "hosts-list [account_id/all]",
		Short: "List of hosts (specify account id or \"all\" for all subaccounts)",
		Long:  ``,
		Args:  cobra.MinimumNArgs(1),
		Example: "  "+programName+" hosts-list all --role MySwitchRole",
		Run: func(cmd *cobra.Command, args []string) {
			hostsList(args[0])
		},
	}

	var cmdHostsCheck = &cobra.Command{
		Use:   "hosts-check [account_id/all]",
		Short: "Check access to hosts (specify account id or \"all\" for all subaccounts)",
		Long:  ``,
		Args:  cobra.MinimumNArgs(1),
		Example: "  "+programName+" hosts-check all -u toor,ec2-user -f ~/.ssh/user.key -s 12345678910 -r MySwitchRole",
		Run: func(cmd *cobra.Command, args []string) {
			hostsCheck(args[0])
		},
	}

	cobra.EnableCommandSorting = false
	
	var rootCmd = &cobra.Command{Use: programName}
	rootCmd.PersistentFlags().StringVarP(&awsAccessKeyID, "aws_access_key_id", "i", "", "AWS access key ID (default from env AWS_ACCESS_KEY_ID)")
	rootCmd.PersistentFlags().StringVarP(&awsSecretAccessKey, "aws_secret_access_key", "k", "", "AWS secret access key (default from env AWS_SECRET_ACCESS_KEY)")
	rootCmd.PersistentFlags().StringVarP(&awsRegion, "aws_region", "", "us-east-1", "AWS region")
	rootCmd.PersistentFlags().BoolVarP(&isDebug, "debug", "", false, "Verbose")

	rootCmd.AddCommand(cmdAccountsList)

	ac := cmdAccountsCheck.PersistentFlags()
	ac.StringVarP(&awsRoleName, "role", "r", "", "Name of the role to switch account")
	cobra.MarkFlagRequired(ac, "role")
	rootCmd.AddCommand(cmdAccountsCheck)

	hl := cmdHostsList.PersistentFlags()
	hl.StringVarP(&awsRoleName, "role", "r", "", "Name of the role to switch account")
	hl.StringVarP(&accountsToSkip, "skip", "s", "", "AWS account ID(s) to skip, comma separated")
	cobra.MarkFlagRequired(hl, "role")
	rootCmd.AddCommand(cmdHostsList)

	hc := cmdHostsCheck.PersistentFlags()
	hc.StringVarP(&awsRoleName, "role", "r", "", "Name of the IAM role to switch account (required)")
	hc.StringVarP(&sshKeyFileName, "keyfile", "f", "", "Name of the ssh key file (required)")
	hc.StringVarP(&sshUserName, "user", "u", "root", "Name(s) of the ssh user(s), comma separated")
	hc.StringVarP(&accountsToSkip, "skip", "s", "", "AWS account ID(s) to skip, comma separated")
	cobra.MarkFlagRequired(hc, "role")
	cobra.MarkFlagRequired(hc, "keyfile")
	rootCmd.AddCommand(cmdHostsCheck)

	rootCmd.Execute()

	fmt.Println()
}
