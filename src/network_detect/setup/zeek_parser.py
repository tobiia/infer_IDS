# pyright: ignore-all-errors
# type: ignore

from json import loads, dumps
from collections import OrderedDict

# FROM: https://github.com/dgunter/ParseZeekLogs
# I attempted to fix numerous issues in this library. This mainly had to do with brittle and incorrect data type conversion, as well as data formatting issues. I also added parsing logs as dictionary functionality. The library now works without error but is not organized well. I will clean it and submit a pull request at a later time.

class ParseZeekLogs(object):
    """Class that parses Zeek logs and allows log data to be output in CSV or json format.

    Attributes:
        filepath: Path of Zeek log file to read

    """

    def __init__(self, filepath, batchsize=500, fields=None, output_format=None, ignore_keys=[], meta={}, safe_headers=False):
        self.fd = open(filepath,"r")
        self.options = OrderedDict()
        self.firstRun = True
        self.filtered_fields = fields
        self.batchsize = batchsize
        self.output_format = output_format
        self.ignore_keys = ignore_keys
        self.meta = meta
        self.safe_headers = safe_headers

        # Convert ' to " in meta string
        meta = loads(dumps(meta).replace("'", '"'))

        # Read the header option lines
        l = self.fd.readline().strip("\n")
        while l.strip().startswith("#"):
            # Parse the options out
            if l.startswith("#separator"):
                key = str(l[1:].split(" ")[0])
                value = str.encode(l[1:].split(" ")[1].strip()).decode('unicode_escape')
                self.options[key] = value
            elif l.startswith("#"):
                key = str(l[1:].split(self.options.get('separator'))[0])
                value = l[1:].split(self.options.get('separator'))[1:]
                self.options[key] = value

            # Read the next line
            l = self.fd.readline().strip("\n")

        self.firstLine = l

        # Save mapping of fields to values:
        self.fields = self.options.get('fields')
        self.types = self.options.get('types')

        # Convert field names if safe_headers is enabled
        #if self.safe_headers is True:
        #    for i, val in enumerate(self.fields):
        #        self.fields[i] = self.fields[i].replace(".", "_")

        self.data_types = {}
        for i, val in enumerate(self.fields):
            # Convert field names if safe_headers is enabled
            if self.safe_headers is True:
                self.fields[i] = self.fields[i].replace(".", "_")

            # Match types with each other
            self.data_types[self.fields[i]] = self.types[i]

        # REVIEW - set empty indicators once
        empty_vals = self.options.get("empty_field", ["(empty)"])
        unset_vals = self.options.get("unset_field", ["-"])
        self.empty_indicators = set([x.strip() for x in empty_vals + unset_vals])

    # FIXME raising a silent exception despite fd being instantiated in init??
    # def __del__(self):
    #     self.fd.close()

    # REVIEW this is a temp fix
    def __del__(self):
        try:
            if hasattr(self, 'fd') and self.fd is not None:
                self.fd.close()
        except AttributeError:
            pass  # fd doesn't exist, ignore

    def __iter__(self):
        return self

    def __next__(self):
        retVal = ""
        if self.firstRun is True:
            retVal = self.firstLine
            self.firstRun = False
        else:
            retVal = self.fd.readline().strip("\n")


        # If an empty string is returned, readline is done reading
        if retVal == "" or retVal is None or retVal.startswith("#close"):
            raise StopIteration

        # Split out the data we are going to return
        retVal = retVal.split(self.options.get('separator'))

        record = None
        # Make sure we aren't dealing with a comment line
        if len(retVal) > 0 and not str(retVal[0]).strip().startswith("#") \
                and len(retVal) is len(self.options.get("fields")):
            record = OrderedDict()
            # Prepare fields for conversion
            for x in range(0, len(retVal)):
                if self.safe_headers is True:
                    converted_field_name = self.options.get("fields")[x].replace(".", "_")
                else:
                    converted_field_name = self.options.get("fields")[x]
                if self.filtered_fields is None or converted_field_name in self.filtered_fields:
                    # FIXME --> do not use hardcoded strings
                    # Translate - to "" to fix a conversation error
                    if retVal[x] == "-":
                        retVal[x] = ""
                    # Save the record field if the field isn't filtered out
                    record[converted_field_name] = retVal[x]

            # Convert values to the appropriate record type
            record = self.convert_values(record, self.ignore_keys, self.data_types)

            # REVIEW --> delete keys with empty values for json + dict output
            if record is not None and self.output_format == "json":
                # Output will be json

                # Add metadata to json
                record = self.del_empty_values(record)
                for k, v in self.meta.items():
                    record[k] = v

                retVal = dumps(record)

            elif record is not None and self.output_format == "csv":
                retVal = ""
                # Add escaping to csv format
                for k, v in record.items():
                    # Add escaping to string values
                    if isinstance(v, str):
                        retVal += str("\"" + str(v).strip() + "\"" + ",")
                    else:
                        retVal += str(str(v).strip() + ",")
                # Remove the trailing comma
                retVal = retVal[:-1]

            # REVIEW --> fix: now returns a dict instead of None
            elif record is not None:
                record = self.del_empty_values(record)
                # FIXME --> add metadata like w json?
                retVal = record
        else:
            retVal = None

        return retVal
    
    def is_empty(self, v):
        if v is None:
            return True
        if isinstance(v, str):
            s = v.strip()
            return s == "" or s in self.empty_indicators
        return False

    # REVIEW --> moved this outside
    def del_empty_values(self, data):
        keys_to_delete = []
        for k, v in data.items():
            if self.is_empty(v) or (isinstance(v, (list, dict)) and not v):
                keys_to_delete.append(k)
        for k in keys_to_delete:
            del data[k]
        return data


    def convert_values(self, data, ignore_keys=[], data_types={}):
        keys_to_delete = []
        for k, v in data.items():
            # print("evaluating k: " + str(k) + " v: " + str(v))

            if isinstance(v, dict):
                data[k] = self.convert_values(v, ignore_keys, data_types)
                continue

            if k in ignore_keys:
                continue

            # in case whitespace is causing issues with is_empty()
            if isinstance(v, str):
                v = v.strip()

            # must handle empty/missing vals before casting to correct dtypes
            if self.is_empty(v):
                keys_to_delete.append(k)
                continue

            data_type = data_types.get(k)
            if data_type is None:
                data[k] = v
                continue
            
            try:
                if data_type in ("port","count"):
                    data[k] = int(v)
                elif data_type in ("double", "interval", "time"):
                    data[k] = float(v)
                elif data_type == "bool":
                    # REVIEW --> now returns a bool based on the val instead of always true
                    # data[k] = bool(v)
                    data[k] = str(v).lower() == 't'
                # REVIEW --> added list conversion
                elif data_type.startswith("vector"):
                    items = [item.strip() for item in str(v).split(",")] if str(v) else []
                    items = [item for item in items if item != ""]
                    if data_type == "vector[string]":
                        data[k] = items
                    elif data_type == "vector[interval]":
                        data[k] = [float(item) for item in items if not self.is_empty(item)]
                    elif data_type == "vector[count]":
                        data[k] = [int(item) for item in items if not self.is_empty(item)]
                    else:
                        data[k] = items
                else:
                    data[k] = v
            except (ValueError, TypeError):
                keys_to_delete.append(k)

        for k in keys_to_delete:
            del data[k]

        return data

    def get_fields(self):
        """Returns all fields present in the log file

        Returns:
            A python list containing all field names in the log file
        """
        field_names = ""
        if self.output_format == "csv":
            for i, v in enumerate(self.fields):
                if self.filtered_fields is None or v in self.filtered_fields:
                    field_names += str(v) + ","
            # Remove the trailing comma
            field_names = field_names[:-1].strip()
        else:
            field_names = []
            for i, v in enumerate(self.fields):
                if self.filtered_fields is None or v in self.filtered_fields:
                    field_names.append(v)
        return field_names

    def __str__(self):
        return dumps(self.data)