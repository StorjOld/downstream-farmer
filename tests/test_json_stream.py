import unittest

from downstream_farmer.streamencoder import JSONEncoder


class TestJsonStream(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test(self):
        iterable = range(0, 10)

        e = JSONEncoder(stream=True)
        self.assertEqual(
            ''.join(e.iterencode(iterable)), e.encode(list(iterable)))

    def test_not_serializable(self):
        class TestClass(object):
            self.foo = 10

        test_object = TestClass()

        e = JSONEncoder(stream=True)

        with self.assertRaises(TypeError):
            print(''.join(e.iterencode(test_object)))

    def test_embedded(self):
        iterable = range(0, 10)

        d1 = dict(embedded_iterable=iterable)

        d2 = dict(embedded_iterable=list(iterable))

        e = JSONEncoder(stream=True)

        self.assertEqual(''.join(e.iterencode(d1)), e.encode(d2))


if (__name__ == '__main__'):
    unittest.main()
