package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mailio/go-mailio-server/repository"
	"github.com/mailio/go-mailio-server/types"
)

type HandshakeApi struct {
	repo repository.Repository
}

func NewHandshakeApi() *HandshakeApi {
	return &HandshakeApi{}
}

// Get Handshake method
// @Security Bearer
// @Summary Get handshake by id
// @Description Returns a single handshake by id
// @Tags HANDSHAKE API
// @Param id path string true "Handshake ID"
// @Success 200 {object} types.Handshake
// @Accept json
// @Produce json
// @Router /api/v1/handshake/{id} [get]
func (ha *HandshakeApi) GetHandshake(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		ApiErrorf(c, http.StatusBadRequest, "invalid id: %s", id)
		return
	}

	c.JSON(http.StatusOK, types.Handshake{BaseDocument: repository.BaseDocument{ID: id}})
}

// Create Handshake method
// @Security Bearer
// @Summary Create a new handshake
// @Description Create a new handshake
// @Tags HANDSHAKE API
// @Accept json
// @Produce json
// @Param handshake body types.Handshake true "Handshake"
// @Success 201 {object} types.Handshake
// @Router /api/v1/handshake [post]
func (ha *HandshakeApi) CreateHandshake(c *gin.Context) {
	// Get the request body and decode it into a Handshake struct
	var handshake types.Handshake
	if err := c.ShouldBindJSON(&handshake); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Save the handshake to the database
	// if err := ha.DB.Save(&handshake).Error; err != nil {
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	// 	return
	// }

	// Return the created handshake
	c.JSON(http.StatusCreated, handshake)
}

// Update Handshake method
// @Security Bearer
// @Summary Update a handshake
// @Description Update a handshake
// @Tags HANDSHAKE API
// @Accept json
// @Produce json
// @Param id path string true "Handshake ID"
// @Param handshake body types.Handshake true "Handshake"
// @Success 200 {object} types.Handshake
// @Router /api/v1/handshake/{id} [put]
func (ha *HandshakeApi) UpdateHandshake(c *gin.Context) {
	var handshake types.Handshake
	if err := c.ShouldBindJSON(&handshake); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get the handshake with the given id
	// if err := ha.DB.First(&handshake, c.Param("id")).Error; err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
	// 	return
	// }

	// Update the handshake
	// ha.DB.Save(&handshake)

	// Return handshake
	c.JSON(http.StatusOK, handshake)
}

// Delete Handshake method
// @Security Bearer
// @Summary Delete a handshake
// @Description Delete a handshake
// @Tags HANDSHAKE API
// @Param id path string true "Handshake ID"
// @Success 204
// @Router /api/v1/handshake/{id} [delete]
func (ha *HandshakeApi) DeleteHandshake(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		ApiErrorf(c, http.StatusBadRequest, "invalid id: %s", id)
		return
	}
	// delete the handshake with given id
	// ha.DB.Delete(&types.Handshake{}, id)
	c.Status(http.StatusNoContent)
}
