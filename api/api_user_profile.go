package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	diskusagehandlers "github.com/mailio/go-mailio-diskusage-handler"
	"github.com/mailio/go-mailio-server/diskusage"
	"github.com/mailio/go-mailio-server/global"
	"github.com/mailio/go-mailio-server/services"
	"github.com/mailio/go-mailio-server/types"
)

type UserProfileApi struct {
	userService        *services.UserService
	userProfileService *services.UserProfileService
	webauthnService    *services.WebAuthnService
	validate           *validator.Validate
}

func NewUserProfileApi(userService *services.UserService, userProfileService *services.UserProfileService, webauthnService *services.WebAuthnService) *UserProfileApi {
	return &UserProfileApi{
		userService:        userService,
		userProfileService: userProfileService,
		webauthnService:    webauthnService,
		validate:           validator.New(),
	}
}

func (a *UserProfileApi) GetFromCache(address string) *types.UserProfile {
	return a.userProfileService.GetFromCache(address)
}

// Get logged in users basic information
// @Security Bearer
// @Summary Get logged inusers basic information
// @Description Get logged in users basic information
// @Tags User Account
// @Success 200 {object} types.OutputBasicUserInfo
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Accept json
// @Produce json
// @Router /api/v1/user/me [get]
func (a *UserProfileApi) GetUserProfile(c *gin.Context) {
	address := c.GetString("subjectAddress")
	if address == "" {
		ApiErrorf(c, http.StatusUnauthorized, "address not found")
		return
	}
	totalDiskUsageFromHandlers := int64(0)
	for _, diskUsageHandler := range diskusage.Handlers() {
		awsDiskUsage, awsDuErr := diskusage.GetHandler(diskUsageHandler).GetDiskUsage(address)
		if awsDuErr != nil {
			if awsDuErr != diskusagehandlers.ErrNotFound {
				global.Logger.Log("error retrieving disk usage stats", awsDuErr.Error())
			}
		}
		if awsDiskUsage != nil {
			totalDiskUsageFromHandlers += awsDiskUsage.SizeBytes
		}
	}
	stats, sErr := a.userProfileService.Stats(address)
	if sErr != nil {
		global.Logger.Log("error retrieving disk usage stats", sErr.Error())
	}
	up, err := a.userProfileService.Get(address)
	if err != nil {
		ApiErrorf(c, http.StatusInternalServerError, "user profile not found")
		return
	}
	activeSize := int64(0)
	if stats != nil {
		activeSize = stats.ActiveSize
	}
	output := &types.OutputBasicUserInfo{
		Address:     address,
		TotalDisk:   up.DiskSpace,
		UsedDisk:    totalDiskUsageFromHandlers + activeSize,
		Created:     up.Created,
		DisplayName: up.DisplayName,
		Picture:     up.Picture,
		Phone:       up.Phone,
		JobTitle:    up.JobTitle,
		Company:     up.Company,
		Description: up.Description,
		Social:      up.Social,
		WhatToShare: up.WhatToShare,
	}
	c.JSON(http.StatusOK, output)
}

// Update logged in users profile
// @Security Bearer
// @Summary Update logged in users profile
// @Description Update logged in users profile
// @Tags User Account
// @Accept json
// @Produce json
// @Param input body types.UserProfile true "User Profile"
// @Success 200 {object} types.UserProfile
// @Failure 400 {object} api.ApiError "invalid input"
// @Failure 429 {object} api.ApiError "rate limit exceeded"
// @Failure 500 {object} api.ApiError "failed to save user profile"
// @Router /api/v1/user/me [put]
func (a *UserProfileApi) UpdateUserProfile(c *gin.Context) {
	address := c.GetString("subjectAddress")
	if address == "" {
		ApiErrorf(c, http.StatusUnauthorized, "address not found")
		return
	}

	var input types.UserProfile
	if err := c.BindJSON(&input); err != nil {
		ApiErrorf(c, http.StatusBadRequest, "invalid input")
		return
	}

	existingUp, eupErr := a.userProfileService.Get(address)
	if eupErr != nil {
		ApiErrorf(c, http.StatusInternalServerError, "failed to get user profile")
		return
	}
	if !existingUp.Enabled {
		ApiErrorf(c, http.StatusForbidden, "user disabled")
		return
	}

	// user can't mess with the registered domain name (no domain name change)
	webauthNUser, waErr := a.webauthnService.GetUser(address)
	if waErr != nil {
		ApiErrorf(c, http.StatusNotFound, "user not found")
		return
	}
	// these fields are not allowed to be changed (always copy from existing)
	input.Domain = strings.Split(webauthNUser.Name, "@")[1]
	input.Enabled = true
	input.DiskSpace = existingUp.DiskSpace
	input.Modified = time.Now().UTC().UnixMilli()
	input.Created = existingUp.Created
	input.ID = existingUp.ID

	if err := a.validate.Struct(input); err != nil {
		ApiErrorf(c, http.StatusBadRequest, ValidatorErrorToUser(err.((validator.ValidationErrors))))
		return
	}
	up, err := a.userProfileService.Save(address, &input)
	if err != nil {
		if err == types.ErrConflict {
			ApiErrorf(c, http.StatusConflict, "conflict")
			return
		}
		ApiErrorf(c, http.StatusInternalServerError, "failed to save user profile")
		return
	}
	c.JSON(http.StatusOK, up)
}
