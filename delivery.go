package authlier

import (
	"context"
	"net/url"
	"strings"

	"github.com/Rahmannugar/authlier/emailverification"
	"github.com/Rahmannugar/authlier/passwordreset"
)

type verificationURLSender struct {
	sender emailverification.Sender
	url    url.URL
}

func newVerificationURLSender(
	sender emailverification.Sender,
	rawURL string,
) (emailverification.Sender, error) {
	if sender == nil {
		return nil, ErrInvalidConfig
	}
	parsed, err := parseActionURL(rawURL)
	if err != nil {
		return nil, err
	}
	return verificationURLSender{sender: sender, url: *parsed}, nil
}

func (sender verificationURLSender) SendVerification(
	ctx context.Context,
	message emailverification.Message,
) error {
	message.URL = actionURL(sender.url, message.Token)
	return sender.sender.SendVerification(ctx, message)
}

type resetURLSender struct {
	sender passwordreset.Sender
	url    url.URL
}

func newResetURLSender(sender passwordreset.Sender, rawURL string) (passwordreset.Sender, error) {
	if sender == nil {
		return nil, ErrInvalidConfig
	}
	parsed, err := parseActionURL(rawURL)
	if err != nil {
		return nil, err
	}
	return resetURLSender{sender: sender, url: *parsed}, nil
}

func (sender resetURLSender) SendPasswordReset(
	ctx context.Context,
	message passwordreset.Message,
) error {
	message.URL = actionURL(sender.url, message.Token)
	return sender.sender.SendPasswordReset(ctx, message)
}

func parseActionURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" || parsed.User != nil ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, ErrInvalidConfig
	}
	return parsed, nil
}

func actionURL(base url.URL, token string) string {
	query := base.Query()
	query.Set("token", token)
	base.RawQuery = query.Encode()
	return base.String()
}
