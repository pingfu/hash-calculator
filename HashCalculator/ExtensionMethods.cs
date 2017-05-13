using System.Windows.Forms;

namespace HashCalculator
{
    public static class ExtensionMethods
    {
        public static void Invoke(this Control control, MethodInvoker action)
        {
            control.Invoke(action);
        }
    }
}
