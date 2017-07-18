namespace amphp.ChildProcessWrapper
{
    public class Exception : System.Exception
    {
        public Exception(string Message) : base(Message) { }
        public Exception(string Message, System.Exception Inner) : base(Message, Inner) { }
    }

    public class InvalidArgumentException : Exception
    {
        public InvalidArgumentException(string Message) : base(Message) {}
    }

    public class InvalidArgumentValueException : InvalidArgumentException
    {
        public InvalidArgumentValueException(string Message) : base(Message) { }
    }
}
