package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"github.com/Opsek/dns-monitoring/internal/observe"
	startpkg "github.com/Opsek/dns-monitoring/internal/start"
)

// setup runs "osk init": two questions, what the servers give now, and the
// setup written once the person types yes.
func setup(args []string, stdout, stderr io.Writer) int {
	cfg, path, msg := parseInit(args)
	if msg != "" {
		return initWrongUse(stderr, msg)
	}
	o, err := observe.New(cfg)
	if err != nil {
		// Only the flags fill the configuration.
		return initWrongUse(stderr, err.Error())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return startpkg.Init{
		Config:      path,
		RootServers: cfg.RootServers,
		ExtraRanges: cfg.ExtraRanges,
		Observer:    o,
		In:          os.Stdin,
		Out:         stdout,
		Term:        isTerminal(os.Stdin) && isTerminal(stdout),
		Now:         time.Now,
	}.Run(ctx)
}

func initWrongUse(stderr io.Writer, msg string) int {
	return fail(stderr, 2, "osk init: "+msg+"\n"+usage)
}

// parseInit reads the flags of init. The network flags are those of check.
func parseInit(args []string) (cfg observe.Config, path, msg string) {
	var config *string
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Func("config", "the config file to write", func(s string) error {
		if config != nil {
			return errors.New("given more than once")
		}
		config = &s
		return nil
	})
	flags.Func("root-server", "a root server to start from, in place of the built-in ones", func(s string) error {
		server, err := parseServer(s)
		cfg.RootServers = append(cfg.RootServers, server)
		return err
	})
	flags.Func("extra-range", "a prefix of non-public addresses that may be asked", func(s string) error {
		prefix, err := netip.ParsePrefix(s)
		cfg.ExtraRanges = append(cfg.ExtraRanges, prefix)
		return err
	})
	if err := flags.Parse(args); err != nil {
		return cfg, "", err.Error()
	}
	switch {
	case config == nil || *config == "":
		return cfg, "", "--config is required"
	case flags.NArg() > 0:
		return cfg, "", "osk init takes no arguments"
	}
	return cfg, *config, ""
}

// isTerminal reports whether f is a character device. /dev/null is one too,
// which costs only a few harmless codes.
func isTerminal(f any) bool {
	file, ok := f.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
