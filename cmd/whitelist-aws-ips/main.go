// Command whitelist-aws-ips is an AWS Lambda function that keeps security
// group egress rules in sync with the published AWS IP ranges.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/burizz/whitelist-aws-ips/internal/config"
	"github.com/burizz/whitelist-aws-ips/internal/ipranges"
	"github.com/burizz/whitelist-aws-ips/internal/securitygroup"
	"github.com/burizz/whitelist-aws-ips/internal/store"
	"github.com/burizz/whitelist-aws-ips/internal/whitelist"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	runner, err := newRunner(context.Background(), logger)
	if err != nil {
		logger.Error("initialisation failed", "error", err)
		os.Exit(1)
	}

	lambda.Start(func(ctx context.Context) (whitelist.Result, error) {
		res, err := runner.Run(ctx)
		if err != nil {
			logger.Error("run failed", "error", err)
		}
		return res, err
	})
}

// newRunner builds the runner and its AWS clients once per cold start so they
// are reused across invocations.
func newRunner(ctx context.Context, logger *slog.Logger) (*whitelist.Runner, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	var opts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	if awsCfg.Region == "" {
		return nil, errors.New("AWS region is not set: set " + config.EnvRegion + " or AWS_REGION")
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}

	return &whitelist.Runner{
		Fetch: func(ctx context.Context) (*ipranges.Document, error) {
			return ipranges.Fetch(ctx, httpClient, cfg.IPRangesURL)
		},
		State:            store.NewParam(ssm.NewFromConfig(awsCfg), cfg.ParamName),
		Groups:           securitygroup.NewManager(ec2.NewFromConfig(awsCfg), cfg.Port, cfg.MaxRulesPerGroup),
		Recorder:         store.NewTable(dynamodb.NewFromConfig(awsCfg), cfg.TableName),
		Services:         cfg.Services,
		SecurityGroupIDs: cfg.SecurityGroupIDs,
		Logger:           logger,
	}, nil
}
