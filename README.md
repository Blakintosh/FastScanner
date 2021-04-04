# FastScanner
Black Ops III FastFile Anti-Malware

A program made to scan a Black Ops III workshop item's folder for malicious files, then goes further to decompress and analyse each FF of a workshop item for its scripts and LUA files. It will check for orange/red flagged function names and provide the user with guidance as to whether the map/mod is safe to run.

### Contributors
- Blak
- Scobalula

### Other credits
- Google: Shield logo

## FAQ
##### How do I run the program?
To run the program you have two options, you can either drag a Workshop folder directly onto the program for it to analyse, or you can outright run the program and input a Steam URL to the program for it to determine and find a Workshop folder to analyse. Regardless of which method you use, you must already have the map/mod installed, but crucially you do not need to have ran the map/mod.

##### How does the Report output work?
In order to determine the risk of a map/mod, the program splits alerts into three categories, and its overall result will be based on any instance of the most severe it finds.
* Safe (Green): The program did not detect anything suspicious. It is very unlikely that the map/mod has any malicious content.
* Warning (Yellow/Amber): The program detected one or more functions that can be used in malicious ways, but they can also be used in reasonable ways. It's worth the user being aware of their use, however in many cases the map/mod is likely to still be safe to play.
* Alert (Red): The program detected one or more functions that are risky and/or likely to be used in a malicious way, and so the user should be very cautious about whether or not they should play the map/mod.

##### Can I contribute to this program?
Yes. The program has been intentionally open sourced under the GPL license so people can contribute as they wish. If you want to contribute directly to this repo, you can either do a pull request or file an issue with a suggested feature/check. The code is fairly flexible so adding a new suspicious function for it to flag, for example, is easy. I suggest contributing directly here, so everyone can benefit!

## Disclaimer
This program is licensed under the GNU GPL v3.0. You can find a copy of this license in this repository. Any contributors to FastScanner and I **cannot** be held liable to any false negatives and/or positives that the program provides, and we are **not** responsible for harm done by content the program analyses. We do not claim that this will give flawless information on whether a map/mod is safe.

FastScanner does **not** provide active protection from threats and must be manually ran every time a new release and/or update to a map/mod is installed. It should be ran before you first play a map/mod for optimal safety.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

