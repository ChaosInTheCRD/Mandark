package log

import (
	"context"
	"fmt"
	"os"

	"github.com/apex/log"
	apex "github.com/apex/log"
	"github.com/apex/log/handlers/cli"
	"github.com/chaosinthecrd/mandark/pkg/policy"
)

type logKey struct{}

func InitLogContext(debug bool) context.Context {
	var level log.Level

	if debug {
		level = log.DebugLevel
	} else {
		level = log.InfoLevel
	}

	logger := log.Logger{
		Handler: cli.New(os.Stdout),
		Level:   level,
	}

	ctx := context.TODO()
	ctx = log.NewContext(ctx, log.NewEntry(&logger))

	return ctx
}

func AddFields(logger log.Interface, command, directory, config string) *log.Entry {
	entry := logger.WithFields(log.Fields{
		"command":    command,
		"policyFile": directory,
		"imageFile":  config,
	})

	return entry
}

func PrintVerificationErr(ctx context.Context, err policy.OutputErr) {
	logs := apex.FromContext(ctx)
	for _, i := range err.Errors {
		logs.Error(i)
	}
	for _, i := range err.Warnings {
		logs.Warn(i)
	}
	for _, i := range err.Other {
		logs.Warnf("Other: %s", i)
	}
}
