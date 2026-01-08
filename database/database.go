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

	// Get the type of the slice elements (e.g., User{})
	elemType := v.Elem().Type().Elem()

	// Map database column names to struct field indices
	colMap := make(map[string]int)
	for i := 0; i < elemType.NumField(); i++ {
		tag := elemType.Field(i).Tag.Get("db")
		if tag != "" {
			colMap[tag] = i
		}
	}

	// Get column descriptions to know the order
	fieldDescriptions := rows.FieldDescriptions()

	for rows.Next() {
		// Create a new instance of the struct
		item := reflect.New(elemType).Elem()

		// Prepare a slice of interfaces to hold the row values
		values := make([]interface{}, len(fieldDescriptions))
		for i, fd := range fieldDescriptions {
			colName := fd.Name
			if fieldIdx, ok := colMap[colName]; ok {
				values[i] = item.Field(fieldIdx).Addr().Interface()
			} else {
				// Column not found in struct, scan into a dummy variable
				var dummy interface{}
				values[i] = &dummy
			}
		}

		if err := rows.Scan(values...); err != nil {
			return err
		}

		// Append the populated struct to the result slice
		v.Elem().Set(reflect.Append(v.Elem(), item))
	}

	return nil
}
