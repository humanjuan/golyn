package handlers

import (
	"Back/app"
	"Back/internal/utils"
	"bufio"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func GetLogs(app *app.Application) gin.HandlerFunc {
	return func(c *gin.Context) {
		log := app.LogApp
		var logFilePath string
		var typeLog string
		pageQuery := c.Query("page")
		pageSizeQuery := c.Query("pageSize")
		logLevelQuery := strings.ToUpper(c.Query("logLevel"))
		logTypeQuery := strings.ToLower(c.Query("logType"))
		logTimeQuery := strings.ToLower(c.Query("logTime"))

		switch logTypeQuery {
		case "db":
			logFilePath = filepath.Join(app.Config.Log.Path, "/Golyn_DB.log")
			typeLog = "db"
		default:
			logFilePath = filepath.Join(app.Config.Log.Path, "/Golyn_server.log")
			typeLog = "server"
		}

		file, err := os.Open(logFilePath)
		if err != nil {
			log.Error("An error has occurred in the server when trying to open the log file. Try again later: %s", err.Error())
			c.IndentedJSON(http.StatusInternalServerError, gin.H{
				"message": utils.GetCodeMessage(http.StatusInternalServerError),
				"error":   "Could not open log file",
			})
			return
		}
		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				log.Error("An error has occurred in the server when trying to close the log file. Try again later: %s", err.Error())
			}
		}(file)

		counts := map[string]int{
			"INFO":     0,
			"ERROR":    0,
			"WARN":     0,
			"DEBUG":    0,
			"CRITICAL": 0,
		}
		var logs []string
		var fileLines []string
		var customLogTime time.Duration = 24 * time.Hour

		if logTimeQuery != "" {
			if strings.HasSuffix(logTimeQuery, "h") {
				logTimeInt, err := strconv.Atoi(strings.TrimSuffix(logTimeQuery, "h"))
				if err != nil {
					log.Error("An error has occurred in the server when trying to parse the logTime parameter. Try again later: %s", err.Error())
					c.IndentedJSON(http.StatusBadRequest, gin.H{
						"message": utils.GetCodeMessage(http.StatusBadRequest),
						"error":   "Invalid logTime format. For hours, use a positive number followed by 'h'",
					})
					return
				}
				customLogTime = time.Duration(logTimeInt) * time.Hour
			} else if strings.HasSuffix(logTimeQuery, "m") {
				logTimeInt, err := strconv.Atoi(strings.TrimSuffix(logTimeQuery, "m"))
				if err != nil {
					log.Error("An error has occurred in the server when trying to parse the logTime parameter. Try again later: %s", err.Error())
					c.IndentedJSON(http.StatusBadRequest, gin.H{
						"message": utils.GetCodeMessage(http.StatusBadRequest),
						"error":   "Invalid logTime format. For minutes, use a positive number followed by 'm'",
					})
					return
				}
				customLogTime = time.Duration(logTimeInt) * time.Minute
			} else {
				log.Error("Invalid logTime format (%s). Use 'XXh' or 'XXm' for hour and minutes respectively", logTimeQuery)
				c.IndentedJSON(http.StatusBadRequest, gin.H{
					"message": utils.GetCodeMessage(http.StatusBadRequest),
					"error":   "Invalid logTime format. Use 'XXh' or 'XXm' for hour and minutes respectively",
				})
				return
			}
		}

		now := time.Now()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			logTime, err := utils.ParseLogTimestamp(line)
			if err != nil || now.Sub(logTime) > customLogTime {
				continue
			}
			fileLines = append(fileLines, line)
		}

		if err := scanner.Err(); err != nil {
			log.Error("An error has occurred in the server when trying to read the log file: %s", err.Error())
			c.IndentedJSON(http.StatusInternalServerError, gin.H{
				"message": utils.GetCodeMessage(http.StatusInternalServerError),
				"error":   "Error reading logs",
			})
			return
		}

		// Pagination setup
		isPaginated := pageQuery != "" || pageSizeQuery != ""
		page := 1
		pageSize := 10

		if isPaginated {
			page, err = strconv.Atoi(pageQuery)
			if err != nil || page < 1 {
				log.Error("An error has occurred in the server when trying to parse the page parameter: %s", err.Error())
				c.IndentedJSON(http.StatusBadRequest, gin.H{
					"message": utils.GetCodeMessage(http.StatusBadRequest),
					"error":   "Invalid page parameter",
				})
				return
			}

			pageSize, err = strconv.Atoi(pageSizeQuery)
			if err != nil || pageSize < 1 {
				log.Error("An error has occurred in the server when trying to parse the pageSize parameter: %s", err.Error())
				c.IndentedJSON(http.StatusBadRequest, gin.H{
					"message": utils.GetCodeMessage(http.StatusBadRequest),
					"error":   "Invalid pageSize parameter",
				})
				return
			}
		}

		totalLines := len(fileLines)
		totalPages := (totalLines + pageSize - 1) / pageSize

		// Leer en orden inverso para la paginación correcta
		offset := (page - 1) * pageSize
		start := totalLines - offset - 1

		for i := start; i >= 0 && len(logs) < pageSize; i-- {
			line := fileLines[i]

			if logLevelQuery != "" && !utils.ContainsLogLevel(line, logLevelQuery) {
				continue
			}

			logs = append(logs, line)

			for level := range counts {
				if utils.ContainsLogLevel(line, level) {
					counts[level]++
					break
				}
			}
		}

		response := gin.H{
			"message":    utils.GetCodeMessage(http.StatusOK),
			"logs":       logs,
			"totalLines": totalLines,
			"totalPages": totalPages,
			"counts":     counts,
			"type":       typeLog,
		}

		if isPaginated {
			response["page"] = page
			response["pageSize"] = pageSize
			response["totalLogs"] = len(logs)
		}

		c.IndentedJSON(http.StatusOK, response)
	}
}
