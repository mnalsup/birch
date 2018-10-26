// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
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

package cmd

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/spf13/cobra"
)

var dns string

// traceCmd represents the trace command
var traceCmd = &cobra.Command{
	Use:   "trace",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Printf("INFO: resolve: %v\n", dns)
		if len(dns) < 1 {
			log.Fatal("Empty required parameter dns")
		}
		sess := session.Must(session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
		}))
		recordSet, err := getRecordSetByName(sess)
		if err != nil {
			log.Println(err)
		} else {
			recordSets := []*route53.ResourceRecordSet{recordSet}
			printRecordSets(recordSets)
		}
		var elbDNS string
		if recordSet == nil {
			elbDNS = dns
		} else {
			elbDNS = *recordSet.AliasTarget.DNSName
		}
		//TODO: if no recordset, submit resolve parameter to getLoadBalancerByDNSName
		elbs, elbv2s, err := getLoadBalancerByDNSName(sess, elbDNS)
		if err != nil {
			log.Fatal(err)
		}
		printElbs(elbs)
		printElbv2s(elbv2s)

		var targetGroups []*elbv2.TargetGroup
		var listeners []*elbv2.Listener
		for _, val := range elbv2s {
			tgs, err := getTargetGroupsByLoadBalancer(sess, val)
			if err != nil {
				log.Fatal(err)
			}
			for _, tg := range tgs {
				targetGroups = append(targetGroups, tg)
			}

			currListeners, err := getListenersByLoadBalancer(sess, val)
			if err != nil {
				log.Fatal(err)
			}
			listeners = append(listeners, currListeners...)
		}
		printListeners(listeners)
		printTargetGroups(targetGroups)

		var ec2s []*ec2.Instance
		for _, value := range elbs {
			elbEc2s, err := getEC2ByLoadBalancer(sess, value)
			if err != nil {
				log.Fatal(err)
			}
			for _, v := range elbEc2s {
				ec2s = append(ec2s, v)
			}
		}
		for _, value := range targetGroups {
			tgEc2s, err := getInstancesByTargetGroup(sess, value)
			if err != nil {
				log.Fatal(err)
			}
			for _, v := range tgEc2s {
				ec2s = append(ec2s, v)
			}
		}
		var securityGroups []*ec2.SecurityGroup
		for _, v := range ec2s {
			sgs, err := getSecurityGroupsByInstance(sess, v)
			if err != nil {
				log.Fatal(err)
			}
			for _, sg := range sgs {
				var exists bool
				exists = false
				for _, existSg := range securityGroups {
					if *existSg.GroupId == *sg.GroupId {
						exists = true
					}
				}
				if !exists {
					securityGroups = append(securityGroups, sg)
				}
			}
		}
		printEc2Instances(ec2s, securityGroups)
	},
}

func init() {
	rootCmd.AddCommand(traceCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// traceCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// traceCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	traceCmd.Flags().StringVarP(&dns, "dns", "d", "", "DNS entry to trace")
}

func getRecordSetByName(session *session.Session) (*route53.ResourceRecordSet, error) {
	resolve := dns
	// Create new Route53 client
	route53Svc := route53.New(session)
	hz, err := route53Svc.ListHostedZones(nil)
	if err != nil {
		log.Fatal(err)
	}
	//TODO: handle IsTruncated
	hostedZones := hz.HostedZones[0:len(hz.HostedZones)]
	for _, hostedZone := range hostedZones {
		input := &route53.ListResourceRecordSetsInput{
			HostedZoneId: hostedZone.Id,
		}
		rs, err := route53Svc.ListResourceRecordSets(input)
		if err != nil {
			log.Fatal(err)
		}
		//TODO: hanlde IsTruncated
		recordSets := rs.ResourceRecordSets[0:len(rs.ResourceRecordSets)]
		searchName := resolve + "."
		for _, recordSet := range recordSets {
			if *recordSet.Name == searchName {
				return recordSet, nil
			}
		}
	}
	return nil, errors.New("INFO: no record set found")
}

func getLoadBalancerByDNSName(session *session.Session, DNSName string) (elbs []*elb.LoadBalancerDescription, elbv2s []*elbv2.LoadBalancer, err error) {
	elbSvc := elb.New(session)
	elbInput := &elb.DescribeLoadBalancersInput{}
	elbOut, err := elbSvc.DescribeLoadBalancers(elbInput)
	if err != nil {
		return nil, nil, err
	}
	elbv2Svc := elbv2.New(session)
	elbv2Input := &elbv2.DescribeLoadBalancersInput{}
	elbv2Out, err := elbv2Svc.DescribeLoadBalancers(elbv2Input)
	if err != nil {
		return nil, nil, err
	}
	for _, value := range elbOut.LoadBalancerDescriptions {
		if strings.Contains(strings.ToLower(DNSName), strings.ToLower(*value.DNSName)) {
			elbs = append(elbs, value)
		}
	}
	for _, value := range elbv2Out.LoadBalancers {
		if strings.Contains(strings.ToLower(DNSName), strings.ToLower(*value.DNSName)) {
			elbv2s = append(elbv2s, value)
		}
	}
	return elbs, elbv2s, nil
}

func getEC2ByLoadBalancer(session *session.Session, elb *elb.LoadBalancerDescription) (ec2s []*ec2.Instance, err error) {
	ec2Svc := ec2.New(session)
	//TODO: handle more than default MaxResults
	var input = &ec2.DescribeInstancesInput{
		InstanceIds: make([]*string, 0),
	}
	for _, value := range elb.Instances {
		input.InstanceIds = append(input.InstanceIds, value.InstanceId)
	}
	ec2sOut, err := ec2Svc.DescribeInstances(input)
	if err != nil {
		return nil, err
	}
	for _, value := range ec2sOut.Reservations {
		for _, v := range value.Instances {
			ec2s = append(ec2s, v)
		}
	}
	return ec2s, nil
}

func getListenersByLoadBalancer(session *session.Session, elbv2LB *elbv2.LoadBalancer) (listeners []*elbv2.Listener, err error) {
	elbv2Svc := elbv2.New(session)
	var input = &elbv2.DescribeListenersInput{
		LoadBalancerArn: elbv2LB.LoadBalancerArn,
	}
	listenersOut, err := elbv2Svc.DescribeListeners(input)
	if err != nil {
		return nil, err
	}
	listeners = listenersOut.Listeners
	return listeners, nil
}

func getTargetGroupsByLoadBalancer(session *session.Session, elbv2LB *elbv2.LoadBalancer) (targetGroups []*elbv2.TargetGroup, err error) {
	elbv2Svc := elbv2.New(session)
	var input = &elbv2.DescribeTargetGroupsInput{
		LoadBalancerArn: elbv2LB.LoadBalancerArn,
	}
	targetGroupsOut, err := elbv2Svc.DescribeTargetGroups(input)
	if err != nil {
		return nil, err
	}
	targetGroups = targetGroupsOut.TargetGroups
	return targetGroups, nil
}

func getInstancesByTargetGroup(session *session.Session, targetGroup *elbv2.TargetGroup) (ec2s []*ec2.Instance, err error) {
	elbv2Svc := elbv2.New(session)
	var input = &elbv2.DescribeTargetHealthInput{
		TargetGroupArn: targetGroup.TargetGroupArn,
	}
	tghOut, err := elbv2Svc.DescribeTargetHealth(input)
	if err != nil {
		log.Fatal(err)
	}
	ec2Svc := ec2.New(session)
	var ec2Input = &ec2.DescribeInstancesInput{
		InstanceIds: make([]*string, 0),
	}
	for _, value := range tghOut.TargetHealthDescriptions {
		ec2Input.InstanceIds = append(ec2Input.InstanceIds, value.Target.Id)
		//TODO: Make this bubble up to the top
		if *value.TargetHealth.State == "unhealthy" {
			fmt.Printf("Warning: target %v is unhealthy\n", *value.Target.Id)
		}
	}
	if len(ec2Input.InstanceIds) > 0 {
		ec2sOut, err := ec2Svc.DescribeInstances(ec2Input)
		if err != nil {
			return nil, err
		}
		for _, value := range ec2sOut.Reservations {
			for _, v := range value.Instances {
				ec2s = append(ec2s, v)
			}
		}
	} else {
		log.Printf("WARN: %v Does not have any associated instances.", *targetGroup.TargetGroupName)
	}
	return ec2s, nil
}

func getSecurityGroupsByInstance(session *session.Session, instance *ec2.Instance) (securityGroups []*ec2.SecurityGroup, err error) {
	ec2Svc := ec2.New(session)
	var sgIds []*string
	for _, sg := range instance.SecurityGroups {
		sgIds = append(sgIds, sg.GroupId)
	}
	var input = &ec2.DescribeSecurityGroupsInput{
		GroupIds: sgIds,
	}
	securityGroupsOut, err := ec2Svc.DescribeSecurityGroups(input)
	if err != nil {
		return nil, err
	}
	for _, sg := range securityGroupsOut.SecurityGroups {
		securityGroups = append(securityGroups, sg)
	}
	return securityGroups, nil
}

func printEc2Instances(ec2Instances []*ec2.Instance, securityGroups []*ec2.SecurityGroup) {
	for _, ec2Instance := range ec2Instances {
		fmt.Println("------EC2 Instance--------")
		if raw {
			fmt.Println(ec2Instance)
			fmt.Printf("_________________________________\n")
		} else {
			var name string
			name = "N/A"
			for _, tag := range ec2Instance.Tags {
				if *tag.Key == "Name" {
					name = *tag.Value
				}
			}
			type firewallEntry struct {
				perm     string
				protocol string
				ports    string
				sources  string
			}
			var portTable []*firewallEntry
			var ec2Sgs []*ec2.SecurityGroup
			for _, sg := range securityGroups {
				for _, ec2Sg := range ec2Instance.SecurityGroups {
					if *sg.GroupId == *ec2Sg.GroupId {
						ec2Sgs = append(ec2Sgs, sg)
					}
				}
			}
			for _, ec2Sg := range ec2Sgs {
				for _, ipPermission := range ec2Sg.IpPermissions {
					var sources string
					for _, sourceIP := range ipPermission.IpRanges {
						sources = sources + "," + *sourceIP.CidrIp
					}
					for _, sourceGroup := range ipPermission.UserIdGroupPairs {
						sources = sources + "," + *sourceGroup.GroupId
					}
					var fromPort string
					if ipPermission.FromPort == nil {
						fromPort = ""
					} else {
						fromPort = strconv.FormatInt(*ipPermission.FromPort, 10)
					}
					var toPort string
					if ipPermission.ToPort == nil {
						toPort = ""
					} else {
						toPort = strconv.FormatInt(*ipPermission.FromPort, 10)
					}
					var entry = &firewallEntry{
						perm:     "INGRESS",
						protocol: *ipPermission.IpProtocol,
						ports:    fromPort + "-" + toPort,
						sources:  sources,
					}
					portTable = append(portTable, entry)
				}
			}
			fmt.Printf("Id: %v\n", *ec2Instance.InstanceId)
			fmt.Printf("Id: %v\n", name)
			for _, portEntry := range portTable {
				fmt.Printf("%v	%v	%v	%v\n", portEntry.perm, portEntry.protocol, portEntry.ports, portEntry.sources)
			}
			fmt.Printf("_________________________________\n")
		}
	}
}

func printListeners(listeners []*elbv2.Listener) {
	for _, listener := range listeners {
		fmt.Println("__________Listener____________")
		if raw {
			fmt.Println(listener)
			fmt.Printf("_________________________________\n")
		} else {
			fmt.Printf("Arn: %v\n", *listener.ListenerArn)
			for _, defAc := range listener.DefaultActions {
				fmt.Printf("%v	%v	-> %v %v\n", *listener.Protocol, *listener.Port, *defAc.Type, *defAc.TargetGroupArn)
			}
		}
		fmt.Printf("_________________________________\n")
	}
}

func printTargetGroups(targetGroups []*elbv2.TargetGroup) {
	for _, targetGroup := range targetGroups {
		fmt.Println("_______Target Group________")
		if raw {
			fmt.Println(targetGroup)
			fmt.Printf("_________________________________\n")
		} else {
			fmt.Printf("Arn: %v\n", *targetGroup.TargetGroupArn)
			fmt.Printf("Name: %v\n", *targetGroup.TargetGroupName)
			fmt.Printf("_________________________________\n")
		}
	}
}

func printElbs(lbs []*elb.LoadBalancerDescription) {
	for _, lb := range lbs {
		fmt.Println("______Load Balancer Classic________")
		if raw {
			fmt.Println(lb)
			fmt.Printf("_________________________________\n")
		} else {
			fmt.Printf("Name: %v\n", *lb.LoadBalancerName)
			for _, listenerDesc := range lb.ListenerDescriptions {
				fmt.Printf("%v	%v	->	%v	%v\n", *listenerDesc.Listener.Protocol, *listenerDesc.Listener.LoadBalancerPort, *listenerDesc.Listener.InstanceProtocol, *listenerDesc.Listener.InstancePort)
			}
			fmt.Printf("_________________________________\n")
		}
	}
}

func printElbv2s(lbs []*elbv2.LoadBalancer) {
	for _, lb := range lbs {
		fmt.Println("______Load Balancer________")
		if raw {
			fmt.Println(lb)
			fmt.Printf("_________________________________\n")
		} else {
			fmt.Printf("Name: %v\n", *lb.LoadBalancerName)
			fmt.Printf("_________________________________\n")
		}
	}
}

func printRecordSets(rss []*route53.ResourceRecordSet) {
	for _, rs := range rss {
		fmt.Println("______Record Set________")
		if raw {
			fmt.Println(rs)
			fmt.Printf("_________________________________\n")
		} else {
			fmt.Printf("Name: %v\n", *rs.Name)
			fmt.Printf("_________________________________\n")
		}
	}
}
