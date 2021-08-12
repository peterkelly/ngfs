from typing import Optional, Any
from io import StringIO
from math import inf, nan, pi
import struct
import json
next_id = 1

import sys
print("genproto.py: sys.version =", sys.version)


class Fields:
    next_id: int
    protobuf_out: StringIO
    python_out: StringIO
    rust_out: StringIO
    prev_field_type: Optional[str]

    def __init__(self) -> None:
        self.next_id = 1
        self.protobuf_out = StringIO()
        self.python_out = StringIO()
        self.rust_out = StringIO()
        self.prev_field_type = None

        self.protobuf_out.write("syntax = \"proto2\";\n")
        self.protobuf_out.write("package sample;\n")
        self.protobuf_out.write("\n")
        self.protobuf_out.write("message FieldTypes {\n")

        self.python_out.write("import sys\n")
        self.python_out.write("print('fields.py: sys.version =', sys.version)\n")

        self.python_out.write("from generated import fields_pb2\n")
        self.python_out.write("from math import inf, nan\n")
        self.python_out.write("\n")
        self.python_out.write("FILENAME = 'generated/tests.rs'");
        self.python_out.write("\n")
        self.python_out.write("with open(FILENAME, 'w') as f:\n")

    def finish(self) -> None:
        self.protobuf_out.write("}\n")
        self.python_out.write("\n")
        self.python_out.write("print('Wrote %s' % (FILENAME))\n")

    def add_test_item(self, field_type: str, suffix: str, value: Any,
                      rust_value: Optional[str] = None) -> None:
        field_id = self.next_id
        self.next_id += 1
        field_name = "test_%s_%s" % (field_type, suffix)
        if self.prev_field_type != field_type:
            self.protobuf_out.write("\n")
        self.protobuf_out.write("    optional %-8s %-24s = %d;\n" % (field_type, field_name, field_id))

        if rust_value is None:
            rust_value = value


        self.python_out.write("    msg = fields_pb2.FieldTypes()\n")
        self.python_out.write("    msg.%s = %r\n" % (field_name, value))
        # self.python_out.write("    print('%s %s' % ('" + field_name + "', msg.SerializeToString().hex()))\n")
        self.python_out.write("    print('    #[test]', file=f)\n")
        self.python_out.write("    print('    fn decode_%s() -> Result<(), Box<dyn Error>> {', file=f)\n" % (field_name))
        self.python_out.write("    print('        let data = from_hex(\\\"%s\\\").unwrap();" +
                              "' % (msg.SerializeToString().hex()), file=f)\n")
        self.python_out.write("    print('        let mut reader = PBufReader::new(&data);', file=f)\n")
        self.python_out.write("    print('        let field = reader.read_field().unwrap().unwrap();', file=f)\n")
        self.python_out.write("    print('        assert_eq!(field.data.to_%s()?, %s);', file=f)\n" % (
                            field_type, rust_value))
        self.python_out.write("    print('        Ok(())', file=f)\n")
        self.python_out.write("    print('    }', file=f)\n");
        self.python_out.write("    print('', file=f)\n");
        self.python_out.write("\n")



    # #[test]
    # fn decode_test_sint32_max() -> Result<(), Box<dyn Error>> {
    #     let data = from_hex("b002cb89c987dbd2e0e74e").unwrap();
    #     let field = PBufReader::new(&data).read_field().unwrap().unwrap();
    #     assert_eq!(field.data.to_u64()?, 5678901234567890123);
    #     Ok(())
    # }


        self.prev_field_type = field_type


def write_file(filename: str, content: str) -> None:
    with open(filename, "w") as f:
        f.write(content)
    print("Wrote %s" % (filename))


U32_MIN = 0
U32_MAX = 4294967295
U64_MIN = 0
U64_MAX = 18446744073709551615
I32_MIN = -2147483648
I32_MAX = 2147483647
I64_MIN = -9223372036854775808
I64_MAX = 9223372036854775807

F32_MIN_BYTES = bytes([0xff, 0x7f, 0xff, 0xff])
F32_MAX_BYTES = bytes([0x7f, 0x7f, 0xff, 0xff])
F64_MIN_BYTES = bytes([0xff, 0xef, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
F64_MAX_BYTES = bytes([0x7f, 0xef, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])

F32_MIN = struct.unpack("!f", F32_MIN_BYTES)
F32_MAX = struct.unpack("!f", F32_MAX_BYTES)
F64_MIN = struct.unpack("!d", F64_MIN_BYTES)
F64_MAX = struct.unpack("!d", F64_MAX_BYTES)

def main() -> None:
    fields = Fields()

    fields.add_test_item("string", "empty", "", '""')
    fields.add_test_item("string", "nonempty", "hello", '"hello"')
    fields.add_test_item("bytes", "empty", bytes(), "vec![]")
    fields.add_test_item("bytes", "nonempty", bytes([0xca, 0xfe, 0xba, 0xbe]), "vec![0xca, 0xfe, 0xba, 0xbe]")
    fields.add_test_item("bool", "true", True, "true")
    fields.add_test_item("bool", "false", False, "false")

    fields.add_test_item("fixed32", "positive", 1234567890)
    fields.add_test_item("fixed32", "min", U32_MIN, "u32::MIN")
    fields.add_test_item("fixed32", "max", U32_MAX, "u32::MAX")
    fields.add_test_item("fixed64", "positive", 5678901234567890123)
    fields.add_test_item("fixed64", "min", U64_MIN, "u64::MIN")
    fields.add_test_item("fixed64", "max", U64_MAX, "u64::MAX")

    fields.add_test_item("sfixed32", "positive", 1234567890)
    fields.add_test_item("sfixed32", "negative", -1234567890)
    fields.add_test_item("sfixed32", "zero", 0)
    fields.add_test_item("sfixed32", "min", I32_MIN, "i32::MIN")
    fields.add_test_item("sfixed32", "max", I32_MAX, "i32::MAX")
    fields.add_test_item("sfixed64", "positive", 5678901234567890123)
    fields.add_test_item("sfixed64", "negative", -5678901234567890123)
    fields.add_test_item("sfixed64", "zero", 0)
    fields.add_test_item("sfixed64", "min", I64_MIN, "i64::MIN")
    fields.add_test_item("sfixed64", "max", I64_MAX, "i64::MAX")

    fields.add_test_item("float", "positive", pi)
    fields.add_test_item("float", "negative", -pi)
    fields.add_test_item("float", "zero", 0.0)
    # fields.add_test_item("float", "min", F32_MIN, "f32::MIN")
    # fields.add_test_item("float", "max", F32_MAX, "f32::MAX")
    fields.add_test_item("float", "posinf", inf, "f32::INFINITY")
    fields.add_test_item("float", "neginf", -inf, "f32::NEG_INFINITY")
    # fields.add_test_item("float", "nan", nan, "f32::NAN")
    fields.add_test_item("double", "positive", pi)
    fields.add_test_item("double", "negative", -pi)
    fields.add_test_item("double", "zero", 0.0)
    # fields.add_test_item("double", "min", F64_MIN, "f64::MIN")
    # fields.add_test_item("double", "max", F64_MAX, "f64::MAX")
    fields.add_test_item("double", "posinf", inf, "f64::INFINITY")
    fields.add_test_item("double", "neginf", -inf, "f64::NEG_INFINITY")
    # fields.add_test_item("double", "nan", nan, "f64::NAN")

    fields.add_test_item("uint32", "positive", 1234567890)
    fields.add_test_item("uint32", "min", U32_MIN, "u32::MIN")
    fields.add_test_item("uint32", "max", U32_MAX, "u32::MAX")
    fields.add_test_item("uint64", "positive", 5678901234567890123)
    fields.add_test_item("uint64", "min", U64_MIN, "u64::MIN")
    fields.add_test_item("uint64", "max", U64_MAX, "u64::MAX")

    fields.add_test_item("int32", "positive", 1234567890)
    fields.add_test_item("int32", "negative", -1234567890)
    fields.add_test_item("int32", "zero", 0)
    fields.add_test_item("int32", "min", I32_MIN, "i32::MIN")
    fields.add_test_item("int32", "max", I32_MAX, "i32::MAX")
    fields.add_test_item("int64", "positive", 5678901234567890123)
    fields.add_test_item("int64", "negative", -5678901234567890123)
    fields.add_test_item("int64", "zero", 0)
    fields.add_test_item("int64", "min", I64_MIN, "i64::MIN")
    fields.add_test_item("int64", "max", I64_MAX, "i64::MAX")
    fields.add_test_item("sint32", "positive", 1234567890)
    fields.add_test_item("sint32", "negative", -1234567890)
    fields.add_test_item("sint32", "zero", 0)
    fields.add_test_item("sint32", "min", I32_MIN, "i32::MIN")
    fields.add_test_item("sint32", "max", I32_MAX, "i32::MAX")
    fields.add_test_item("sint64", "positive", 5678901234567890123)
    fields.add_test_item("sint64", "negative", -5678901234567890123)
    fields.add_test_item("sint64", "zero", 0)
    fields.add_test_item("sint64", "min", I64_MIN, "i64::MIN")
    fields.add_test_item("sint64", "max", I64_MAX, "i64::MAX")

    fields.finish()

    write_file("generated/fields.proto", fields.protobuf_out.getvalue())
    write_file("generated/fields.py", fields.python_out.getvalue())


    pass

if __name__ == "__main__":
    main()
