package handlers

import (
	"Back/app"
	"Back/database"
	"Back/internal/utils"
	"github.com/gin-gonic/gin"
	"net/http"
)

func GetCountries(app *app.Application) gin.HandlerFunc {
	return func(c *gin.Context) {
		log := app.LogApp
		logDB := app.LogDB

		log.Debug("GetCountries()")
		db := app.DB

		var countries []database.Country
		err := db.Select(database.Queries["get_countries"], &countries)
		if err != nil {
			logDB.Error("An error has occurred in the database. Try again later: %s", err)
			c.IndentedJSON(http.StatusInternalServerError, gin.H{
				"message": utils.GetCodeMessage(http.StatusInternalServerError),
				"error":   "An error has occurred in the database. Try again later.",
			})
			return
		}

		logDB.Debug("countries: %s", countries)
		c.IndentedJSON(http.StatusOK, gin.H{
			"message": utils.GetCodeMessage(http.StatusOK),
			"data":    countries,
		})
		return
	}
}
