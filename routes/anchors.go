package routes

import (
	"strings"
	"time"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"

	"github.com/gmb-sig/trust-anchor/routes/response"
	"github.com/gmb-sig/trust-anchor/trust"
)

const (
	headerETag          = "ETag"
	headerIfNoneMatch   = "If-None-Match"
	headerTrustSnapshot = "X-Trust-Snapshot"
	headerTrustStale    = "X-Trust-Stale"
	contentTypePEM      = "application/x-pem-file"
)

// bundleQuery reads the shared bundle filter parameters.
func (r *router) bundleQuery(ctx *azugo.Context) (territories []string, use string, qscdOnly bool, ok bool) {
	territories = ctx.Query.Values("territory")
	if u := ctx.Query.StringOptional("use"); u != nil {
		use = *u
	}
	if !trust.ValidUse(use) {
		ctx.Error(azugo.ParamInvalidError{Name: "use", Tag: "oneof"})
		return nil, "", false, false
	}
	q, err := ctx.Query.BoolOptional("qscdOnly")
	if err != nil {
		ctx.Error(azugo.ParamInvalidError{Name: "qscdOnly", Tag: "bool", Err: err})
		return nil, "", false, false
	}
	if q != nil {
		qscdOnly = *q
	}
	return territories, use, qscdOnly, true
}

// snapshotForServing returns the active snapshot or responds 503.
func (r *router) snapshotForServing(ctx *azugo.Context) *trust.Snapshot {
	snap := r.Manager().Active()
	if snap == nil {
		ctx.StatusCode(fasthttp.StatusServiceUnavailable)
		ctx.Text("no trust snapshot loaded yet")
		return nil
	}
	return snap
}

// stale computes the serve-time staleness flag: any requested territory past
// NextUpdate + grace.
func (r *router) stale(snap *trust.Snapshot, territories []string) bool {
	now := time.Now().UTC()
	grace := r.Config().StaleGrace
	for _, t := range snap.Territories {
		if len(territories) > 0 && !containsFold(territories, t.Code) {
			continue
		}
		if t.StaleAt(now, grace) {
			return true
		}
	}
	return false
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// notModified handles If-None-Match against the snapshot ETag.
func notModified(ctx *azugo.Context, etag string) bool {
	inm := ctx.Header.Get(headerIfNoneMatch)
	if inm == "" {
		return false
	}
	for _, part := range strings.Split(inm, ",") {
		if strings.Trim(strings.TrimSpace(part), `"`) == strings.Trim(etag, `"`) {
			return true
		}
	}
	return false
}

func setBundleHeaders(ctx *azugo.Context, snap *trust.Snapshot, stale bool) {
	ctx.Header.Set(headerETag, `"`+snap.ID+`"`)
	ctx.Header.Set(headerTrustSnapshot, snap.ID)
	if stale {
		ctx.Header.Set(headerTrustStale, "true")
	} else {
		ctx.Header.Set(headerTrustStale, "false")
	}
	ctx.Header.AppendAccessControlExposeHeaders(headerETag, headerTrustSnapshot, headerTrustStale)
}

// anchorsPEM serves the filtered PEM bundle.
//
// @operationId GetAnchorsPEM
// @title Trusted CA PEM bundle
// @description Concatenated PEM certificates filtered by territory, use and QSCD qualification. Strong ETag = snapshot id; supports If-None-Match.
// @param territory query string false "Comma-separated territory codes (e.g. LV,EE); default all"
// @param use query string false "signature | authentication | seal | website"
// @param qscdOnly query bool false "Only QCWithQSCD-qualified services"
// @success 200 string string "PEM bundle"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @resource Anchors
// @route /v1/anchors [get].
func (r *router) anchorsPEM(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}
	snap := r.snapshotForServing(ctx)
	if snap == nil {
		return
	}
	territories, use, qscdOnly, ok := r.bundleQuery(ctx)
	if !ok {
		return
	}

	stale := r.stale(snap, territories)
	setBundleHeaders(ctx, snap, stale)
	if notModified(ctx, snap.ID) {
		ctx.StatusCode(fasthttp.StatusNotModified)
		return
	}

	anchors, err := trust.Filter(snap, territories, use, qscdOnly)
	if err != nil {
		ctx.Error(azugo.ParamInvalidError{Name: "use", Tag: "oneof"})
		return
	}
	ctx.ContentType(contentTypePEM)
	ctx.Raw(trust.PEMBundle(anchors))
}

// anchorsJSON serves the filtered bundle as JSON with full metadata.
//
// @operationId GetAnchorsJSON
// @title Trusted CA bundle (JSON)
// @description Certificates (base64 DER) with TSP/service metadata, qualifications and fingerprints. Same filters and ETag semantics as the PEM endpoint.
// @param territory query string false "Comma-separated territory codes"
// @param use query string false "signature | authentication | seal | website"
// @param qscdOnly query bool false "Only QCWithQSCD-qualified services"
// @success 200 AnchorsResponse response.Anchors "Bundle with metadata"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @resource Anchors
// @route /v1/anchors.json [get].
func (r *router) anchorsJSON(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}
	snap := r.snapshotForServing(ctx)
	if snap == nil {
		return
	}
	territories, use, qscdOnly, ok := r.bundleQuery(ctx)
	if !ok {
		return
	}

	stale := r.stale(snap, territories)
	setBundleHeaders(ctx, snap, stale)
	if notModified(ctx, snap.ID) {
		ctx.StatusCode(fasthttp.StatusNotModified)
		return
	}

	anchors, err := trust.Filter(snap, territories, use, qscdOnly)
	if err != nil {
		ctx.Error(azugo.ParamInvalidError{Name: "use", Tag: "oneof"})
		return
	}
	ctx.JSON(response.NewAnchors(snap, anchors, stale))
}
