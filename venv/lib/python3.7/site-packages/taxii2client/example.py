from taxii2client import v21

collection = v21.Collection("http://localhost:5000/trustgroup1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/", user="admin", password="Password0")

# bundle = collection.get_objects(per_request=77)
# for bundle in collection.get_objects():
# print(len(bundle["objects"]), bundle)

# for bundle in as_pages(collection.get_objects, per_request=77):
#     print(len(bundle["objects"]), bundle)
#
# for bundle in as_pages(collection.get_manifest, per_request=77, **{"type": "indicator"}):
#     print(len(bundle["objects"]), bundle)
#
# bundle = collection.get_objects(limit=10)
# print(len(bundle["objects"]), bundle)

envelope = collection.get_objects(limit=100)

while envelope.get("more", False):
    envelope = collection.get_objects(limit=100, next=envelope.get("next", ""))
    print(envelope)

# envelope = collection.get_manifest(limit=100)
#
# while envelope.get("more", False):
#     envelope = collection.get_manifest(limit=100, next=envelope.get("next", ""))
#     print(envelope)

envelope = collection.get_object("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da", version="all", limit=10)
print(envelope)
