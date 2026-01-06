package database

import (
	"context"
	"errors"
	"reflect"
)

func (dbi *DBInstance) Select(query string, result interface{}, args ...interface{}) error {
	// Execute SQL query with optional arguments ($n)
	rows, err := dbi.db.Query(context.Background(), query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Ensure 'result' is a pointer to a slice of structs
	v := reflect.ValueOf(result)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Slice {
		return errors.New("'result' must be a pointer to a struct slice")
	}

	// Get the type of the slice elements (e.g., Country{})
	elemType := v.Elem().Type().Elem()

	// Map database column names to struct field indices
	colMap := make(map[string]int)
	for i := 0; i < elemType.NumField(); i++ {
		colName := elemType.Field(i).Tag.Get("db") // Column name defined in 'db' tag
		colMap[colName] = i
	}

	for rows.Next() {
		// Create a new instance of the struct (item := country{})
		item := reflect.New(elemType).Elem()

		// Map row values to struct fields
		values := make([]interface{}, len(colMap))
		for _, colIndex := range colMap {
			values[colIndex] = item.Field(colIndex).Addr().Interface()
		}

		if err := rows.Scan(values...); err != nil {
			return err
		}

		// Append the populated struct to the result slice
		v.Elem().Set(reflect.Append(v.Elem(), item))
	}

	return nil
}
