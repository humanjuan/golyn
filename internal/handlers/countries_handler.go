package handlers

import (
	"Back/database"
	"Back/globals"
	"Back/internal/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

func GetCountries() gin.HandlerFunc {
	return func(c *gin.Context) {
		log := globals.GetAppLogger()
		logDB := globals.GetDBLogger()

		log.Debug("GetCountries()")
		db := globals.GetDBInstance()

		var countries []database.Country
		err := db.Select(database.Queries["get_countries"], &countries)
		if err != nil {
			logDB.Error("An error has occurred in the database. Try again later: %s", err)
			err = fmt.Errorf("an error has occurred in the database. Try again later")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}

		c.IndentedJSON(http.StatusOK, gin.H{
			"message": utils.GetCodeMessage(http.StatusOK),
			"data":    countries,
		})
		return
	}
}
