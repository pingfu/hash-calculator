// Copyright (C)2014-2014 AirVPN (support@airvpn.org) / https://airvpn.org )
//
// Hash Calculator is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// Hash Calculator is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with Hash Calculator. If not, see <http://www.gnu.org/licenses/>.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace HashCalculator
{
	public partial class MainForm : Form
	{
		public MainForm()
		{
			InitializeComponent();
            
            DragOver += OnDragOver;
            DragDrop += OnDragDrop;
        }
        
		private void CmdCompute_Click(object sender, EventArgs e)
		{
			Check();
		}

		private void CmdBrowsePath_Click(object sender, EventArgs e)
		{
			var FD = new System.Windows.Forms.OpenFileDialog();
			if (FD.ShowDialog() == System.Windows.Forms.DialogResult.OK)
			{
				string fileToOpen = FD.FileName;
				TxtPath.Text = FD.FileName;
				Check();
			}
		}

		private void txtPath_TextChanged(object sender, EventArgs e)
		{
			Clear();
		}

		private void LnkWebsite_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
		{
			Process.Start("https://airvpn.org/faq/software_signatures/");
		}

		private void TxtCheck_TextChanged(object sender, EventArgs e)
		{
			Check();
		}
        
		private void ChkMD5_CheckedChanged(object sender, EventArgs e)
		{
			Check();
		}

		private void ChkSHA1_CheckedChanged(object sender, EventArgs e)
		{
			Check();
		}

		private void ChkSHA256_CheckedChanged(object sender, EventArgs e)
		{
			Check();
		}

		private void ChkSHA512_CheckedChanged(object sender, EventArgs e)
		{
			Check();
		}

        private void OnDragDrop(object sender, DragEventArgs dragEventArgs)
        {
            if (dragEventArgs.Data.GetDataPresent(DataFormats.FileDrop))
            {
                var strFiles = (string[])dragEventArgs.Data.GetData(DataFormats.FileDrop);
                TxtPath.Text = strFiles.First();
                Check();
            }
        }

        private static void OnDragOver(object sender, DragEventArgs dragEventArgs)
        {
            if (dragEventArgs.Data.GetDataPresent(DataFormats.FileDrop))
            {
                dragEventArgs.Effect = DragDropEffects.Copy;
            }
        }

        public void Clear()
		{
			TxtMD5.Text = "";
			TxtSHA1.Text = "";
			TxtSHA256.Text = "";
			TxtSHA512.Text = "";
		}

		public void ColorTextBox(TextBox c)
		{
		    c.Invoke(() =>
            {
                int lc = 246;
                int mc = 160;
                int hc = 255;
                if ((TxtCheck.Text.Trim() == "") || (c.Text == ""))
                    c.BackColor = Color.FromArgb(lc, lc, lc);
                else if (TxtCheck.Text.Trim() == c.Text)
                    c.BackColor = Color.FromArgb(mc, hc, mc);
                else
                    c.BackColor = Color.FromArgb(hc, mc, mc);
            });
		}

		private static string GetHash(string filePath, HashAlgorithm hasher)
		{
			using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
				return GetHash(fs, hasher);
		}

		private static string GetHash(Stream s, HashAlgorithm hasher)
		{
			var hash = hasher.ComputeHash(s);
			return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();			
		}
        
        public Task<HashChecksum> Compute(string filename, CheckBox c, TextBox t, HashAlgorithm hashAlgorithm)
        {
            if (c.Checked == false || _cancellationTokenSource.IsCancellationRequested)
            {
                return new Task<HashChecksum>(() => null);
            }

		    return Task.Run(() =>
            {
                try
                {
                    using (var lhc = new LargeHashCollider(hashAlgorithm))
                    {
                        this.Invoke(() =>
                        {
                            t.Text = "Calculation...";
                        });

                        //var result = new HashChecksum("");
                        var result = lhc.ComputeOn(new FileInfo(filename), _cancellationTokenSource.Token, HashProgress);

                        this.Invoke(() =>
                        {
                            Text = $"File Hash Calculator";

                            t.BackColor = Color.LightYellow;
                            t.Text = result.ToString();

                            ColorTextBox(t);

                            t.Refresh();
                        });

                        return result;
                    }
                }
                catch (Exception e)
                {
                    this.Invoke(() =>
                    {
                        Text = $"File Hash Calculator";
                        t.Text = string.Empty;
                    });

                    return null;
                }
            });
        }

        private void HashProgress(HashProgressEventArgs e)
        {
            this.Invoke(() =>
            {
                Text = $"File Hash Calculator — processing {e.BytesRead}/{e.FileSize} ({e.ProgressPercentage}%)";
            });
        }

        public async void Check()
		{
			Application.DoEvents();

            Cursor.Current = Cursors.WaitCursor;

		    var filename = TxtPath.Text;

            _cancellationTokenSource = new CancellationTokenSource();

            await Compute(filename, ChkMD5, TxtMD5, MD5.Create());
            await Compute(filename, ChkSHA1, TxtSHA1, SHA1.Create());
            await Compute(filename, ChkSHA256, TxtSHA256, SHA256.Create());
            await Compute(filename, ChkSHA512, TxtSHA512, SHA512.Create());

            Cursor.Current = Cursors.Default;
        }

        private volatile CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();

        private sealed class LargeHashCollider : IDisposable
        {
            private const int BufferSize = 65536;
            private readonly HashAlgorithm _hashAlgorithm;

            public LargeHashCollider(HashAlgorithm hashAlgorithm)
            {
                if (hashAlgorithm == null)
                {
                    hashAlgorithm = SHA256.Create();
                }

                _hashAlgorithm = hashAlgorithm;
            }

            public HashChecksum ComputeOn(FileSystemInfo fileInfo, CancellationToken cancellationToken, Action<HashProgressEventArgs> hashProgress = null)
            {
                using (var stream = File.Open(fileInfo.FullName, FileMode.Open))
                {
                    var totalBytesRead = 0L;
                    var readAheadBuffer = new byte[BufferSize];
                    var readAheadBytesRead = stream.Read(readAheadBuffer, 0, readAheadBuffer.Length);

                    totalBytesRead += readAheadBytesRead;

                    do
                    {
                        var bytesRead = readAheadBytesRead;
                        var buffer = readAheadBuffer;

                        readAheadBuffer = new byte[BufferSize];
                        readAheadBytesRead = stream.Read(readAheadBuffer, 0, readAheadBuffer.Length);

                        totalBytesRead += readAheadBytesRead;

                        if (readAheadBytesRead == 0)
                        {
                            _hashAlgorithm.TransformFinalBlock(buffer, 0, bytesRead);
                        }
                        else
                        {
                            _hashAlgorithm.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                        }

                        hashProgress?.Invoke(new HashProgressEventArgs(totalBytesRead, stream.Length));

                    } while (readAheadBytesRead != 0 && !cancellationToken.IsCancellationRequested);

                    if (cancellationToken.IsCancellationRequested)
                    {
                        throw new OperationCanceledException("Cancellation requested.");
                    }

                    return new HashChecksum(_hashAlgorithm.Hash);
                }
            }

            public void Dispose()
            {
                _hashAlgorithm?.Dispose();
            }
        }

        private void MainForm_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Escape)
            {
                if (_cancellationTokenSource.IsCancellationRequested == false)
                {
                    _cancellationTokenSource.Cancel();
                }

                // prevent child controls from handling this event as well
                e.SuppressKeyPress = true;
            }
        }
    }

    /// <summary>
    /// Convenience class to hold and compare the outputs from hashing functions
    /// </summary>
    public sealed class HashChecksum
    {
        public byte[] Hash { get; }

        public HashChecksum(byte[] hash)
        {
            Hash = hash;
        }

        public HashChecksum(string hexidecimal)
        {
            try
            {
                Hash =
                    Enumerable.Range(0, hexidecimal.Length)
                        .Where(x => x % 2 == 0)
                        .Select(x => Convert.ToByte(hexidecimal.Substring(x, 2), 16))
                        .ToArray();
            }
            catch (Exception e)
            {
                throw new Exception($"Could not parse the input string as hexadecimal: {e.Message}");
            }
        }

        public override string ToString()
        {
            return BitConverter.ToString(Hash).ToLower().Replace("-", "");
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;

            var otherHash = obj as HashChecksum;
            return otherHash != null && otherHash.Hash.SequenceEqual(Hash);
        }

        public override int GetHashCode()
        {
            return Hash?.GetHashCode() ?? 0;
        }
    }

    public sealed class HashProgressEventArgs
    {
        public long BytesRead { get; }
        public long FileSize { get; }

        public double ProgressPercentage => Convert.ToInt32((double)BytesRead / FileSize * 100); // at least one value needs to be as casted a Double to divide two Int64 values

        public HashProgressEventArgs(long totalBytesRead, long size)
        {
            BytesRead = totalBytesRead;
            FileSize = size;
        }
    }
}
