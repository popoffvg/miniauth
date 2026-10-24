package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/user"
)

const userCreateUsage = "usage: miniauth user create --login <login>\n\nThe password is read from stdin.\n"

var errUsage = errors.New("miniauth: usage: miniauth user create --login <login>")

// runCLI runs an admin command. The HTTP server starts only when args is empty.
func runCLI(ctx context.Context, args []string, databaseURL string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("miniauth: command is missing")
	}
	switch args[0] {
	case "user":
		return runUser(ctx, args[1:], databaseURL, in, out)
	default:
		return fmt.Errorf("miniauth: unknown command %q", args[0])
	}
}

func runUser(ctx context.Context, args []string, databaseURL string, in io.Reader, out io.Writer) error {
	if len(args) == 0 || args[0] != "create" {
		return errUsage
	}
	return runUserCreate(ctx, args[1:], databaseURL, in, out)
}

func runUserCreate(ctx context.Context, args []string, databaseURL string, in io.Reader, out io.Writer) error {
	loginRaw, err := parseLoginFlag(args, out)
	if err != nil {
		return err
	}
	login, err := user.ParseLogin(loginRaw)
	if err != nil {
		return fmt.Errorf("miniauth: login %q is not valid: use 1 to 64 characters from a-z, 0-9, and . _ @ + -", loginRaw)
	}
	password, err := readPassword(in)
	if err != nil {
		return err
	}
	if databaseURL == "" {
		return errors.New("miniauth: MINIAUTH_DATABASE_URL is not set")
	}

	pool, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err = postgres.Migrate(ctx, pool); err != nil {
		return err
	}

	created, err := user.NewUsers(postgres.NewUserRepository(pool)).Create(ctx, login, password)
	if errors.Is(err, user.ErrLoginTaken) {
		return fmt.Errorf("miniauth: login %q already exists", login)
	}
	if err != nil {
		return fmt.Errorf("miniauth: create user: %w", err)
	}
	if _, err := fmt.Fprintf(out, "created %s %s\n", created.Login, created.ID); err != nil {
		return fmt.Errorf("miniauth: write result: %w", err)
	}
	return nil
}

func parseLoginFlag(args []string, out io.Writer) (string, error) {
	fs := flag.NewFlagSet("user create", flag.ContinueOnError)
	fs.SetOutput(out)
	login := fs.String("login", "", "login of the new user")
	fs.Usage = func() {
		_, _ = io.WriteString(out, userCreateUsage)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", errHelp
		}
		return "", errUsage
	}
	if fs.NArg() != 0 || *login == "" {
		return "", errUsage
	}
	return *login, nil
}

// errHelp means the command printed help and should exit 0.
var errHelp = errors.New("miniauth: help")

func readPassword(in io.Reader) (user.Password, error) {
	body, err := io.ReadAll(io.LimitReader(in, user.MaxPasswordBytes+1))
	if err != nil {
		return user.Password{}, fmt.Errorf("miniauth: read password: %w", err)
	}
	if len(body) > user.MaxPasswordBytes {
		return user.Password{}, errors.New("miniauth: password is too long")
	}
	body = bytes.TrimSuffix(body, []byte("\n"))
	body = bytes.TrimSuffix(body, []byte("\r"))
	password, err := user.NewPassword(string(body))
	if errors.Is(err, user.ErrEmptyPassword) {
		return user.Password{}, errors.New("miniauth: password is empty")
	}
	if errors.Is(err, user.ErrPasswordTooLong) {
		return user.Password{}, errors.New("miniauth: password is too long")
	}
	if err != nil {
		return user.Password{}, fmt.Errorf("miniauth: password: %w", err)
	}
	return password, nil
}
