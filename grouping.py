from stix2 import TAXIICollectionSource, Filter, parse
from taxii2client.v20 import Collection
import json
from stix2.v21 import Bundle
import os

depth = {"APT1":1,"APT12":1, "APT17":2, "APT18":1, "APT38":1}

def attnck_taxii():
    # Initialize dictionary to hold Enterprise ATT&CK content
    ent_attack = {}
    pre_attack = {}

    # Establish TAXII2 Collection instance for Enterprise ATT&CK collection
    ENTERPRISE_ATTCK = "95ecc380-afe9-11e4-9b6c-751b66dd541e"
    PRE_ATTCK = "062767bd-02d2-4b72-84ba-56caef0f8658"
    MOBILE_ATTCK = "2f669986-b40b-4423-b720-4396ca6a462b"

    enterprise_attack_collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")
    pre_attack_collection = Collection("https://cti-taxii.mitre.org/stix/collections/062767bd-02d2-4b72-84ba-56caef0f8658/")

    # Supply the collection to TAXIICollection
    tc_source = TAXIICollectionSource(enterprise_attack_collection)
    tc_source2 = TAXIICollectionSource(pre_attack_collection)

    # Create filters to retrieve content from Enterprise ATT&CK based on type
    filter_objs = {"techniques": Filter("type", "=", "attack-pattern"),
        "mitigations": Filter("type", "=", "course-of-action"),
        "groups": Filter("type", "=", "intrusion-set"),
        "malware": Filter("type", "=", "malware"),
        "tools": Filter("type", "=", "tool"),
        "relationships": Filter("type", "=", "relationship")
    }

    filter_objs_pre = {"techniques": Filter("type", "=", "attack-pattern"),
        "groups": Filter("type", "=", "intrusion-set"),
        "relationships": Filter("type", "=", "relationship")
    }

    # Retrieve all Enterprise ATT&CK content
    for key in filter_objs:
        ent_attack[key] = tc_source.query(filter_objs[key])

    for key in filter_objs_pre:
        pre_attack[key] = tc_source2.query(filter_objs[key])


    return ent_attack, pre_attack

class GBundle:
    def __init__(self, collection, gname):
        self.collection = collection
        self.gname = gname
        self.gid = self.find_group(gname)

        self.relation = self.search_relationship(self.gid)
        self.rid = [rel["id"] for rel in self.relation]
        self.q = [(rel,0) for rel in self.relation]

        self.pre_relation = self.search_relationship_pre(self.gid)
        self.pre_rid = [rel["id"] for rel in self.pre_relation]
        self.pre_q = [(rel, 0) for rel in self.pre_relation]

        self.objects = []
        self.obj_id = []
        self.pre_obj_id = []

    def get_type(self, _id):
        return _id[:_id.index("--")]

    def find_group(self, s):
        for key in self.collection.ent_attack["intrusion-set"].keys():
            if self.collection.ent_attack["intrusion-set"][key]["name"] == s:
                return key

    def search_relationship(self, key):
        return [data for data in self.collection.ent_attack["relationships"] if data["source_ref"] == key or data["target_ref"] == key]

    def find_group_pre(self, s):
        for key in self.collection.pre_attack["intrusion-set"].keys():
            if self.collection.pre_attack["intrusion-set"][key]["name"] == s:
                return key

    def search_relationship_pre(self, key):
        return [data for data in self.collection.pre_attack["relationships"] if data["source_ref"] == key or data["target_ref"] == key]

    def collect_relation(self):
        while len(self.q):
            temp = self.q[0]

            del self.q[0]
            if temp[0]["id"] not in self.rid:
                self.rid.append(temp[0]["id"])
                self.relation.append(temp[0])

            target_candi = self.search_relationship(temp[0]["target_ref"])
            source_candi = self.search_relationship(temp[0]["source_ref"])
            cnt = 0
            for candi in target_candi:
                if self.get_type(candi["source_ref"]) == "intrusion-set" or self.get_type(candi["target_ref"]) == "intrusion-set":
                    continue

                if self.get_type(temp[0]["target_ref"]) == "attack-pattern" and self.get_type(candi["source_ref"]) == "malware":
                    if cnt < 4:
                        cnt+=1
                    else:
                        continue

                if candi["id"] not in self.rid and temp[1] < depth[self.gname]:
                    self.q.append((candi,temp[1]+1))

            cnt = 0
            for candi in source_candi:
                if self.get_type(candi["source_ref"]) == "intrusion-set" or self.get_type(candi["target_ref"]) == "intrusion-set":
                    continue

                if self.get_type(temp[0]["source_ref"]) == "attack-pattern" and self.get_type(candi["target_ref"]) == "malware":
                    if cnt < 4:
                        cnt+=1
                    else:
                        continue

                if candi["id"] not in self.rid and temp[1] < depth[self.gname]:
                    self.q.append((candi,temp[1]+1))

    def pre_collect_relation(self):
        while len(self.pre_q):
            temp = self.pre_q[0]

            del self.pre_q[0]
            if temp[0]["id"] not in self.pre_rid:
                self.pre_rid.append(temp[0]["id"])
                self.pre_relation.append(temp[0])

            target_candi = self.search_relationship_pre(temp[0]["target_ref"])
            source_candi = self.search_relationship_pre(temp[0]["source_ref"])

            for candi in target_candi:
                if self.get_type(candi["source_ref"]) == "intrusion-set" or self.get_type(candi["target_ref"]) == "intrusion-set":
                    continue

                if candi["id"] not in self.pre_rid and temp[1] < depth[self.gname]:
                    self.pre_q.append((candi,temp[1]+1))

            for candi in source_candi:
                if self.get_type(candi["source_ref"]) == "intrusion-set" or self.get_type(candi["target_ref"]) == "intrusion-set":
                    continue

                if candi["id"] not in self.pre_rid and temp[1] < depth[self.gname]:
                    self.pre_q.append((candi,temp[1]+1))

    def generate_bundle(self):
        for rel in self.relation:
            if rel["target_ref"] not in self.obj_id:
                self.obj_id.append(rel["target_ref"])
            if rel["source_ref"] not in self.obj_id:
                self.obj_id.append(rel["source_ref"])
            self.objects.append(rel)

        for rel in self.pre_relation:
            if rel["target_ref"] not in self.pre_obj_id:
                self.pre_obj_id.append(rel["target_ref"])
            if rel["source_ref"] not in self.pre_obj_id:
                self.pre_obj_id.append(rel["source_ref"])
            self.objects.append(rel)

        for obj in self.obj_id:
            self.objects.append(self.collection.ent_attack[self.get_type(obj)][obj])

        for obj in self.pre_obj_id:
            self.objects.append(self.collection.pre_attack[self.get_type(obj)][obj])
            # print(self.collection.pre_attack[self.get_type(obj)][obj]["id"])

        #print(len(self.rid), len(self.relation))
        #print(len(self.obj_id))
        #print(len(self.pre_obj_id))
        #print(len(self.objects))

class TAXIICollection:
    def __init__(self):
        ent_attack, pre_attack = attnck_taxii()
        self.ent_attack = self.ent_to_json(ent_attack)
        self.pre_attack = self.pre_to_json(pre_attack)

    def ent_to_json(self, attack):
        attack_json = {"attack-pattern": {}, "course-of-action": {}, "intrusion-set": {}, "malware": {}, "tool": {},
                       "relationships": []}

        for data in attack["techniques"]:
            attack_json["attack-pattern"][data["id"]] = data

        for data in attack["mitigations"]:
            attack_json["course-of-action"][data["id"]] = data

        for data in attack["groups"]:
            attack_json["intrusion-set"][data["id"]] = data

        for data in attack["malware"]:
            attack_json["malware"][data["id"]] = data

        for data in attack["tools"]:
            attack_json["tool"][data["id"]] = data

        for data in attack["relationships"]:
            attack_json["relationships"].append(data)

        return attack_json

    def pre_to_json(self, attack):
        attack_json = {"attack-pattern": {}, "intrusion-set": {}, "relationships": []}

        for data in attack["techniques"]:
            attack_json["attack-pattern"][data["id"]] = data

        for data in attack["groups"]:
            attack_json["intrusion-set"][data["id"]] = data

        for data in attack["relationships"]:
            attack_json["relationships"].append(data)

        return attack_json

class Group:
    def __init__(self,obj_list):
        self.obj_list = obj_list
        self.attack_pattern = []
        self.group_list = []

    def get_attack_pattern(self):
        for obj in self.obj_list:
            if obj["type"] == "attack-pattern":
                self.attack_pattern.append(obj)

    def find_obj(self,obj_id):
        for obj in self.obj_list:
            if obj["id"] == obj_id:
                return obj

    def grouping(self):
        self.get_attack_pattern()
        for ap in self.attack_pattern:
            rel = []
            object_ids = []
            objects = []
            for obj in self.obj_list:
                if obj["type"] == "relationship":
                    if obj["source_ref"] == ap["id"] or obj["target_ref"] == ap["id"]:
                        rel.append(obj)
                        # print(obj["id"])
                        objects.append(parse(obj, allow_custom=True))

            for r in rel:
                if r["source_ref"] not in object_ids:
                    object_ids.append(r["source_ref"])
                if r["target_ref"] not in object_ids:
                    object_ids.append(r["target_ref"])

            for obj_id in object_ids:
                objects.append(parse(self.find_obj(obj_id), allow_custom=True))

            if not os.path.exists("grouping"):
                os.mkdir("grouping")

            for kcp in ap["kill_chain_phases"]:
                if not os.path.exists("grouping/"+kcp["kill_chain_name"]):
                    os.mkdir("grouping/"+kcp["kill_chain_name"])
                if not os.path.exists("grouping/"+kcp["kill_chain_name"]+"/"+kcp["phase_name"]):
                    os.mkdir("grouping/"+kcp["kill_chain_name"]+"/"+kcp["phase_name"])

                bundle = Bundle(objects=objects)
                with open("grouping/"+kcp["kill_chain_name"]+"/"+kcp["phase_name"]+"/"+str(bundle["id"])+".json","w") as wf:
                    wf.write(str(bundle))


def make_group(group_name):
    collection = TAXIICollection()

    gb = GBundle(collection, group_name)
    gb.collect_relation()
    gb.pre_collect_relation()
    gb.generate_bundle()

    if not os.path.exists('./bundles'):
        os.mkdir('./bundles')

    with open('./bundles/{0}-bundle.json'.format(group_name), "w") as wf:
        wf.write(str(Bundle(objects=gb.objects)))


    with open('./bundles/{0}-bundle.json'.format(group_name), "r") as f:
       obj_list = json.loads(f.read())["objects"]

    g = Group(obj_list)
    g.grouping()

    # update for demo will update more fancy.
    with open('./grouping/{0}-bundle.json'.format(group_name), 'w') as f:
        wf.write(str(Bundle(objects=gb.objects)))



if __name__ == "__main__":
    make_group('APT38')
