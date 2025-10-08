package main

//go:generate depstubber -vendor go.mongodb.org/mongo-driver/bson/primitive D
//go:generate depstubber -vendor go.mongodb.org/mongo-driver/mongo Pipeline Connect
//go:generate depstubber -vendor go.mongodb.org/mongo-driver/mongo/options "" Client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func security_test(w http.ResponseWriter, r *http.Request) {

	// Set client options
	clientOptions := options.Client().ApplyURI("mongodb://test:test@localhost:27017")

	// Connect to MongoDB
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// Check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")

	// Get a handle for your collection
	db := client.Database("test")
	coll := db.Collection("collection")
	untrustedInput := r.Referer() // $ Source

	filter := bson.D{{"name", untrustedInput}}

	fieldName := "test"
	document := filter
	documents := []interface{}{
		document,
		bson.D{{"name", "Bob"}},
	}
	matchStage := bson.D{{"$match", filter}}
	pipeline := mongo.Pipeline{matchStage}
	ctx := context.TODO()
	replacement := bson.D{{"location", "NYC"}}
	result := bson.D{}
	var requestBody map[string]interface{}
	// Different kinds of updates
	update := bson.D{{"$inc", bson.D{{"age", 1}}}}
	unsafe_update := bson.D{{untrustedInput, bson.D{{"age", 1}}}}
	safe_update := bson.D{{"$inc", bson.D{{"age", untrustedInput}}}}
	json.NewDecoder(r.Body).Decode(&requestBody) // $ Source
	find_update_object_unsafe := bson.D{{"$match", requestBody}}

	// Different kinds of filters
	find_filter_safe := bson.D{{"$match", untrustedInput}}
	find_filter_unsafe := bson.D{{untrustedInput, "unsafe"}}
	//Not strongly typed - could be anything
	json.NewDecoder(r.Body).Decode(&requestBody) // $ Source
	find_filter_object_unsafe := bson.D{{"$match", requestBody}}

	models := []mongo.WriteModel{
		//Safe always
		mongo.NewInsertOneModel().SetDocument(find_filter_object_unsafe),
		//Safe if SetFilter(filter is safe), however this can only replace one document at a time so risk is low
		mongo.NewReplaceOneModel().SetFilter(bson.D{{"title", "My Brilliant Friend"}}).
			SetReplacement(Book{Title: "Atonement", Author: "Ian McEwan", Length: 351}),
		//Unsafe since filter is unsafe and unsafe if update is unsafe (using same behavior as filter)
		mongo.NewUpdateManyModel().SetFilter(bson.D{{"length", bson.D{{"$lt", 200}}}}).
			SetUpdate(unsafe_update),
		//Unsafe since filter is unsafe
		mongo.NewDeleteManyModel().SetFilter(find_filter_unsafe),
	}
	//always safe
	coll.Clone(nil)
	coll.EstimatedDocumentCount(ctx, nil)

	//Aggregation operation
	// for now, we can say anyting that goes into pipeline is unsafe always, since certain operations allow "columns" as the value
	coll.Aggregate(ctx, pipeline, nil) // $ Alert

	// Depends on operation in model
	coll.BulkWrite(ctx, models, nil)

	// CRUD operations
	// unsafe if unsafe filter and safe is safe filter, likewise for update
	coll.FindOneAndDelete(ctx, find_filter_object_unsafe, nil) // $ Alert
	coll.FindOneAndReplace(ctx, find_filter_unsafe, nil)
	coll.FindOneAndUpdate(ctx, find_filter_unsafe, nil)
	coll.ReplaceOne(ctx, find_filter_unsafe, replacement)
	coll.UpdateMany(ctx, find_filter_unsafe, safe_update)
	coll.UpdateOne(ctx, find_filter_unsafe, find_update_object_unsafe)
	coll.DeleteMany(ctx, find_filter_safe, nil) // $ Alert
	coll.DeleteOne(ctx, find_filter_unsafe, nil)
	coll.DeleteMany(ctx, find_filter_safe, nil) // $ Alert
	coll.Watch(ctx, pipeline)                   // $ Alert
	//unsafe is filter is unsafe and return value is used
	count, _ := coll.CountDocuments(ctx, find_filter_unsafe, nil)
	distinctNamesInLondon, err := coll.Distinct(ctx, fieldName, filter) // $ Alert
	coll.FindOne(ctx, find_filter_unsafe, nil).Decode(&result)
	cursor, err := coll.Find(ctx, find_filter_unsafe, nil)
	if err = cursor.All(context.TODO(), &result); err != nil {
		panic(err)
	}
	fmt.Println(count)
	fmt.Println(distinctNamesInLondon)

	//Since these are not filters but documents being inserted, injection does not seem possible unless intentional
	coll.InsertMany(ctx, documents)
	coll.InsertOne(ctx, document, nil)

}
