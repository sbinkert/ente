package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/ente/cli/internal/api/models"
	"github.com/go-resty/resty/v2"
)

func toApiError(r *resty.Response, err error) error {
	if err != nil {
		return err
	}
	if r.IsError() {
		return &ApiError{StatusCode: r.StatusCode(), Message: r.String()}
	}
	return nil
}

// IsNotFound reports whether err is an API error with HTTP status 404.
func IsNotFound(err error) bool {
	apiErr, ok := err.(*ApiError)
	return ok && apiErr.StatusCode == http.StatusNotFound
}

func (c *Client) GetEntityKey(ctx context.Context, entityType string) (*models.EntityKey, error) {
	var res models.EntityKey
	r, err := c.restClient.R().
		SetContext(ctx).
		SetQueryParam("type", entityType).
		SetResult(&res).
		Get("/user-entity/key")
	if err := toApiError(r, err); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *Client) CreateEntityKey(ctx context.Context, entityType, encryptedKey, header string) error {
	r, err := c.restClient.R().
		SetContext(ctx).
		SetBody(map[string]string{
			"type":         entityType,
			"encryptedKey": encryptedKey,
			"header":       header,
		}).
		Post("/user-entity/key")
	return toApiError(r, err)
}

func (c *Client) GetEntityDiff(ctx context.Context, entityType string, sinceTime int64, limit int) ([]models.EntityData, error) {
	var res struct {
		Diff []models.EntityData `json:"diff"`
	}
	r, err := c.restClient.R().
		SetContext(ctx).
		SetQueryParam("type", entityType).
		SetQueryParam("sinceTime", strconv.FormatInt(sinceTime, 10)).
		SetQueryParam("limit", strconv.Itoa(limit)).
		SetResult(&res).
		Get("/user-entity/entity/diff")
	if err := toApiError(r, err); err != nil {
		return nil, err
	}
	return res.Diff, nil
}

func (c *Client) CreateEntity(ctx context.Context, entityType, encryptedData, header string) (*models.EntityData, error) {
	var res models.EntityData
	r, err := c.restClient.R().
		SetContext(ctx).
		SetBody(map[string]string{
			"type":          entityType,
			"encryptedData": encryptedData,
			"header":        header,
		}).
		SetResult(&res).
		Post("/user-entity/entity")
	if err := toApiError(r, err); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *Client) UpdateEntity(ctx context.Context, entityType, id, encryptedData, header string, expectedUpdatedAt int64) (*models.EntityData, error) {
	var res models.EntityData
	r, err := c.restClient.R().
		SetContext(ctx).
		SetBody(map[string]any{
			"id":                id,
			"type":              entityType,
			"encryptedData":     encryptedData,
			"header":            header,
			"expectedUpdatedAt": expectedUpdatedAt,
		}).
		SetResult(&res).
		Put("/user-entity/entity")
	if err := toApiError(r, err); err != nil {
		return nil, err
	}
	return &res, nil
}
