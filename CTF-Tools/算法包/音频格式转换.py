from pydub import AudioSegment


def convert_audio(input_file, output_file, output_format):
    # 加载音频文件
    audio = AudioSegment.from_file(input_file)

    # 导出为指定格式
    audio.export(output_file, format=output_format)


# 示例用法
input_file = "input.wav"
output_file = "output.mp3"
output_format = "mp3"

convert_audio(input_file, output_file, output_format)
