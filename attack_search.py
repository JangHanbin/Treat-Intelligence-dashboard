from stix2 import TAXIICollectionSource, Filter, Bundle
from taxii2client.v20 import Collection
import os
collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")

# Supply the collection to TAXIICollection
tc_source = TAXIICollectionSource(collection)

# Create filters to retrieve content from Enterprise ATT&CK based on type
filter_objs = {"techniques": Filter("type", "=", "attack-pattern"),
               "mitigations": Filter("type", "=", "course-of-action"),
               "groups": Filter("type", "=", "intrusion-set"),
               "malware": Filter("type", "=", "malware"),
               "tools": Filter("type", "=", "tool"),
               "relationships": Filter("type", "=", "relationship")
               }



class Attack:
    def __init__(self):
        # Initialize dictionary to hold Enterprise ATT&CK content
        self.attack = dict()

        # Establish TAXII2 Collection instance for Enterprise ATT&CK collection
        # ENTERPRISE_ATTCK = "95ecc380-afe9-11e4-9b6c-751b66dd541e"
        # PRE_ATTCK = "062767bd-02d2-4b72-84ba-56caef0f8658"
        # MOBILE_ATTCK = "2f669986-b40b-4423-b720-4396ca6a462b"

        self.searched_ids = list()
        self.searched_objs = list()


        # Retrieve all Enterprise ATT&CK content
        for key in filter_objs:
            self.attack[key] = tc_source.query(filter_objs[key])


    def deter_types(self):
        types = dict()
        for objects in self.attack:
            for o in self.attack[objects]:
                types.update({o['type']: objects})

        return types.copy()


    def find_groups(self, target_group):
        groups = list()
        for group in self.attack['groups']:
            if group['name'] == target_group:
                groups.append(group)

        return groups.copy()

    def find_relationships(self, obj):
        types = self.deter_types()

        for relationship in self.attack['relationships']:
            if obj['id'] == relationship['source_ref']:
                domain = relationship['target_ref'][:relationship['target_ref'].find('--')]
                self.find_match_id(relationship['target_ref'], types[domain])

            if obj['id'] == relationship['target_ref']:
                domain = relationship['source_ref'][:relationship['source_ref'].find('--')]
                self.find_match_id(relationship['source_ref'], types[domain])



    def find_match_id(self, reference_id, domain):

        for obj in self.attack[domain]:
            if obj['id'] == reference_id:
                if obj['id'] not in self.searched_ids:
                    self.searched_ids.append(obj['id'])
                    self.searched_objs.append(obj)
                    self.find_relationships(obj)



    def get_bundle_json(self, target_group):
        objects = self.find_groups(target_group)

        for obj in objects:
            self.find_relationships(obj)

        bundle = Bundle(self.searched_objs)
        if not os.path.isfile('./bundles/{0}-bundle.json'.format(target_group)):
            with open('./bundles/{0}-bundle.json'.format(target_group), 'w') as f:
                f.write(bundle.serialize())

        return bundle.serialize()













