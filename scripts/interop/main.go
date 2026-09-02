// Interop helper: parse/serialize/restrict grants with storj.io/common/grant
// and upload/download objects with storj.io/uplink. CI-only; crate users
// do not need Go.
//
//	go run -C scripts/interop .
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"storj.io/common/grant"
	"storj.io/uplink"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage: interop <command> [flags] [grant]

commands:
  parse      GRANT   ParseAccess; print "ok satellite=<addr>"
  serialize  GRANT   ParseAccess then Serialize
  restrict   GRANT   read-only Share (-bucket -prefix); print grant
  upload             -grant -bucket -key [-file PATH | -size N]
  download           -grant -bucket -key -file PATH
  ensure-bucket      -grant -bucket

Grant may be a positional arg, -grant, STORJ_ACCESS / STORJ_SIM_ACCESS /
STORJ_INTEROP_ACCESS, or stdin. Object commands skip (exit 0) when the
satellite is unreachable.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "parse":
		cmdParse(os.Args[2:])
	case "serialize":
		cmdSerialize(os.Args[2:])
	case "restrict":
		cmdRestrict(os.Args[2:])
	case "upload":
		cmdUpload(os.Args[2:])
	case "download":
		cmdDownload(os.Args[2:])
	case "ensure-bucket":
		cmdEnsureBucket(os.Args[2:])
	case "-h", "-help", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func cmdParse(args []string) {
	serialized := readGrant(newFlagSet("parse"), args)
	access := mustParseGrant(serialized)
	fmt.Printf("ok satellite=%s\n", access.SatelliteAddress)
}

func cmdSerialize(args []string) {
	serialized := readGrant(newFlagSet("serialize"), args)
	access := mustParseGrant(serialized)
	out, err := access.Serialize()
	must(err)
	fmt.Print(out)
}

func cmdRestrict(args []string) {
	fs := newFlagSet("restrict")
	bucket := fs.String("bucket", "", "share prefix bucket")
	prefix := fs.String("prefix", "", "share prefix (unencrypted object-key prefix)")
	serialized := readGrant(fs, args)
	access := mustParseGrant(serialized)
	var prefixes []grant.SharePrefix
	if *bucket != "" {
		prefixes = append(prefixes, grant.SharePrefix{Bucket: *bucket, Prefix: *prefix})
	}
	restricted, err := access.Restrict(grant.Permission{
		AllowDownload: true,
		AllowList:     true,
	}, prefixes...)
	must(err)
	out, err := restricted.Serialize()
	must(err)
	fmt.Print(out)
}

func cmdUpload(args []string) {
	fs := newFlagSet("upload")
	bucket := fs.String("bucket", "", "bucket")
	key := fs.String("key", "", "object key")
	file := fs.String("file", "", "plaintext file to upload")
	size := fs.Int("size", -1, "generate this many deterministic bytes if -file is empty")
	serialized := readGrant(fs, args)
	requireFlag("bucket", *bucket)
	requireFlag("key", *key)

	var data []byte
	switch {
	case *file != "":
		var err error
		data, err = os.ReadFile(*file)
		must(err)
	case *size >= 0:
		data = payload(*size)
	default:
		var err error
		data, err = io.ReadAll(os.Stdin)
		must(err)
	}

	project, done := openProject(serialized)
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	upload, err := project.UploadObject(ctx, *bucket, *key, nil)
	skipOrFatal(err)
	_, err = upload.Write(data)
	if err != nil {
		_ = upload.Abort()
		skipOrFatal(err)
	}
	must(upload.Commit())
	fmt.Printf("ok bytes=%d\n", len(data))
}

func cmdDownload(args []string) {
	fs := newFlagSet("download")
	bucket := fs.String("bucket", "", "bucket")
	key := fs.String("key", "", "object key")
	file := fs.String("file", "", "destination path")
	serialized := readGrant(fs, args)
	requireFlag("bucket", *bucket)
	requireFlag("key", *key)
	requireFlag("file", *file)

	project, done := openProject(serialized)
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	download, err := project.DownloadObject(ctx, *bucket, *key, nil)
	skipOrFatal(err)
	defer func() { _ = download.Close() }()
	data, err := io.ReadAll(download)
	skipOrFatal(err)
	must(os.WriteFile(*file, data, 0o644))
	fmt.Printf("ok bytes=%d\n", len(data))
}

func cmdEnsureBucket(args []string) {
	fs := newFlagSet("ensure-bucket")
	bucket := fs.String("bucket", "", "bucket")
	serialized := readGrant(fs, args)
	requireFlag("bucket", *bucket)

	project, done := openProject(serialized)
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := project.EnsureBucket(ctx, *bucket)
	skipOrFatal(err)
	fmt.Printf("ok bucket=%s\n", *bucket)
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = usage
	return fs
}

func readGrant(fs *flag.FlagSet, args []string) string {
	grantFlag := fs.String("grant", "", "serialized access grant")
	must(fs.Parse(args))
	if g := strings.TrimSpace(*grantFlag); g != "" {
		return g
	}
	if fs.NArg() > 0 {
		return strings.TrimSpace(fs.Arg(0))
	}
	for _, env := range []string{"STORJ_ACCESS", "STORJ_INTEROP_ACCESS", "STORJ_SIM_ACCESS"} {
		if g := strings.TrimSpace(os.Getenv(env)); g != "" {
			return g
		}
	}
	b, err := io.ReadAll(os.Stdin)
	must(err)
	g := strings.TrimSpace(string(b))
	if g == "" {
		fatal(fmt.Errorf("missing grant (positional, -grant, env, or stdin)"))
	}
	return g
}

func mustParseGrant(serialized string) *grant.Access {
	access, err := grant.ParseAccess(serialized)
	must(err)
	return access
}

func openProject(serialized string) (*uplink.Project, func()) {
	access, err := uplink.ParseAccess(serialized)
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	cfg := uplink.Config{DialTimeout: 10 * time.Second}
	project, err := cfg.OpenProject(ctx, access)
	if err != nil {
		cancel()
		skipOrFatal(err)
	}
	return project, func() {
		_ = project.Close()
		cancel()
	}
}

func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func requireFlag(name, value string) {
	if strings.TrimSpace(value) == "" {
		fatal(fmt.Errorf("missing -%s", name))
	}
}

func skipOrFatal(err error) {
	if err == nil {
		return
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"connection refused",
		"i/o timeout",
		"no such host",
		"context deadline",
		"network is unreachable",
		"connection reset",
		"temporary failure",
		"no route to host",
		"connect: ",
		"dial tcp",
	} {
		if strings.Contains(msg, needle) {
			fmt.Fprintf(os.Stderr, "skip: no satellite (%v)\n", err)
			os.Exit(0)
		}
	}
	fatal(err)
}

func must(err error) {
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "interop: %v\n", err)
	os.Exit(1)
}
