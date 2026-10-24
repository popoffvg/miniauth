package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jessevdk/go-flags"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/user"
)

// errHelp means the command printed help and should exit 0.
var errHelp = errors.New("miniauth: help")

type options struct {
	User userCmd `command:"user" description:"Manage users"`
}

type userCmd struct {
	Create createCmd `command:"create" description:"Create a user" long-description:"The password is read from stdin."`
}

type createCmd struct {
	Login string `long:"login" required:"true" description:"Login of the new user"`

	ctx         context.Context
	databaseURL string
	in          io.Reader
	out         io.Writer
}

// Usage is the placeholder go-flags prints after the command name.
func (c *createCmd) Usage() string {
	return "--login <login>"
}

// Execute creates the user. args are the words left after the flags.
func (c *createCmd) Execute(args []string) error {
	if len(args) != 0 {
		return errors.New("unexpected argument")
	}
	login, err := user.ParseLogin(c.Login)
	if err != nil {
		return fmt.Errorf("login %q is not valid: use 1 to 64 characters from a-z, 0-9, and . _ @ + -", c.Login)
	}
	password, err := readPassword(c.in)
	if err != nil {
		return err
	}
	if c.databaseURL == "" {
		return errors.New("MINIAUTH_DATABASE_URL is not set")
	}

	pool, err := postgres.Open(c.ctx, c.databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err = postgres.Migrate(c.ctx, pool); err != nil {
		return err
	}

	created, err := user.NewUsers(postgres.NewUserRepository(pool)).Create(c.ctx, login, password)
	if errors.Is(err, user.ErrLoginTaken) {
		return fmt.Errorf("login %q already exists", login)
	}
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	if _, err := fmt.Fprintf(c.out, "created %s %s\n", created.Login, created.ID); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// runCLI runs an admin command. The HTTP server starts only when args is empty.
func runCLI(ctx context.Context, args []string, databaseURL string, in io.Reader, out io.Writer) error {
	opts := options{
		User: userCmd{
			Create: createCmd{
				ctx:         ctx,
				databaseURL: databaseURL,
				in:          in,
				out:         out,
			},
		},
	}
	parser := flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash)
	parser.Name = "miniauth"
	_, err := parser.ParseArgs(args)
	if err == nil {
		return nil
	}
	var flagErr *flags.Error
	if errors.As(err, &flagErr) && flagErr.Type == flags.ErrHelp {
		return writeHelp(out, flagErr.Message)
	}
	if errors.As(err, &flagErr) {
		return fmt.Errorf("miniauth: %s", flagErr.Message)
	}
	return fmt.Errorf("miniauth: %w", err)
}

func writeHelp(out io.Writer, message string) error {
	if !strings.HasSuffix(message, "\n") {
		message += "\n"
	}
	if _, err := io.WriteString(out, message); err != nil {
		return fmt.Errorf("miniauth: write help: %w", err)
	}
	return errHelp
}

func readPassword(in io.Reader) (user.Password, error) {
	body, err := io.ReadAll(io.LimitReader(in, user.MaxPasswordBytes+1))
	if err != nil {
		return user.Password{}, fmt.Errorf("read password: %w", err)
	}
	if len(body) > user.MaxPasswordBytes {
		return user.Password{}, errors.New("password is too long")
	}
	body = bytes.TrimSuffix(body, []byte("\n"))
	body = bytes.TrimSuffix(body, []byte("\r"))
	password, err := user.NewPassword(string(body))
	if errors.Is(err, user.ErrEmptyPassword) {
		return user.Password{}, errors.New("password is empty")
	}
	if errors.Is(err, user.ErrPasswordTooLong) {
		return user.Password{}, errors.New("password is too long")
	}
	if err != nil {
		return user.Password{}, fmt.Errorf("password: %w", err)
	}
	return password, nil
}
